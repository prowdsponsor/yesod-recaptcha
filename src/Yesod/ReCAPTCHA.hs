module Yesod.ReCAPTCHA
    ( recaptchaAForm
    , recaptchaMForm
    , recaptchaOptions
    , RecaptchaOptions(..)
    ) where

import Control.Applicative
import Control.Arrow (second)
import Data.Typeable (Typeable)
import Yesod.Widget (whamlet)
import qualified Control.Exception.Lifted as E
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Lazy.Char8 as L8
import qualified Data.Conduit as C
import qualified Data.Default as D
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.Text.Encoding.Error as TEE
import qualified Data.Text.Lazy as TL
import qualified Data.Text.Lazy.Encoding as TLE
import qualified Network.HTTP.Conduit as H
import qualified Network.HTTP.Types as HT
import qualified Network.Info as NI
import qualified Network.Socket as HS
import qualified Network.Wai as W
import qualified Yesod.Auth as YA
import qualified Yesod.Core as YC
import qualified Yesod.Form.Fields as YF
import qualified Yesod.Form.Functions as YF
import qualified Yesod.Form.Types as YF


-- | Class used by @yesod-recaptcha@'s fields.  It should be
-- fairly easy to implement a barebones instance of this class
-- for you foundation data type:
--
-- > instance YesodRecaptcha MyType where
-- >   recaptchaPublicKey  = return "[your public key]"
-- >   recaptchaPrivateKey = return "[your private key]"
--
-- You may also write a more sophisticated instance.  For
-- example, you may give different keys depending on the request
-- (maybe you're serving to two different domains in the same
-- application).
--
-- The 'YA.YesodAuth' superclass is used only for the HTTP
-- request.  Please fill a bug report if you think that this
-- @YesodRecaptcha@ may be useful without @YesodAuth@.
class YA.YesodAuth master => YesodRecaptcha master where
    recaptchaPublicKey  :: YC.GHandler sub master T.Text
    recaptchaPrivateKey :: YC.GHandler sub master T.Text


-- | A reCAPTCHA field.  This 'YF.AForm' returns @()@ because
-- CAPTCHAs give no useful information besides having being typed
-- correctly or not.  When the user does not pass the CAPTCHA,
-- this 'YF.AForm' will automatically the same way as any other
-- @yesod-form@ widget fails, so you may just ignore the @()@
-- value.
recaptchaAForm :: YesodRecaptcha master => YF.AForm sub master ()
recaptchaAForm = YF.formToAForm recaptchaMForm


-- | Same as 'recaptchaAForm', but insteof being an
-- 'YF.AForm', it's an 'YF.MForm'.
recaptchaMForm :: YesodRecaptcha master =>
                  YF.MForm sub master ( YF.FormResult ()
                                      , [YF.FieldView sub master] )
recaptchaMForm = mform
    where
      mform = do
        let fv1 = return ()
            fv2 = recaptchaWidget
        challengeField <- fakeField "recaptcha_challenge_field" fv1
        responseField  <- fakeField "recaptcha_response_field"  fv2
        ret <- case (fst challengeField, fst responseField) of
                 (YF.FormSuccess challenge, YF.FormSuccess response) -> do
                   YC.lift $ check challenge response
                   undefined
                 _ -> return YF.FormMissing
        return (ret, [snd challengeField, snd responseField])


-- | Widget with reCAPTCHA's HTML.
recaptchaWidget :: YesodRecaptcha master => YC.GWidget sub master ()
recaptchaWidget = do
  publicKey <- YC.lift recaptchaPublicKey
  isSecure  <- W.isSecure <$> YC.lift YC.waiRequest
  let proto | isSecure  = "https"
            | otherwise = "http" :: T.Text
  [whamlet|
    <script src="#{proto}://www.google.com/recaptcha/api/challenge?k=#{publicKey}">
    </script>
    <noscript>
       <iframe src="#{proto}://www.google.com/recaptcha/api/noscript?k=#{publicKey}"
           height="300" width="500" frameborder="0"></iframe><br>
       <textarea name="recaptcha_challenge_field" rows="3" cols="40">
       </textarea>
       <input type="hidden" name="recaptcha_response_field"
           value="manual_challenge">
    </noscript>
  |]


-- | Contact reCAPTCHA servers and find out if the user correctly
-- guessed the CAPTCHA.  Unfortunately, reCAPTCHA doesn't seem to
-- provide an HTTPS endpoint for this API even though we need to
-- send our private key.
check :: YesodRecaptcha master =>
         T.Text -- ^ @recaptcha_challenge_field@
      -> T.Text -- ^ @recaptcha_response_field@
      -> YC.GHandler sub master CheckRet
check "" _ = return $ Error "invalid-request-cookie"
check _ "" = return $ Error "incorrect-captcha-sol"
check challenge response = do
  manager    <- YA.authHttpManager <$> YC.getYesod
  privateKey <- recaptchaPrivateKey
  sockaddr   <- W.remoteHost <$> YC.waiRequest
  case sockaddr of
    HS.SockAddrUnix _ -> do
      $(YC.logError) $ "Yesod.ReCAPTCHA: Couldn't find out remote IP, \
                       \are you using a reverse proxy?  If yes, then \
                       \please file a bug report at \
                       \<https://github.com/meteficha/yesod-recaptcha>."
      fail "Could not find remote IP address for reCAPTCHA."
    _ -> do
      let remoteip = case sockaddr of
                       HS.SockAddrInet _ hostAddr ->
                         show $ NI.IPv4 hostAddr
                       HS.SockAddrInet6 _ _ (w1, w2, w3, w4) _ ->
                         show $ NI.IPv6 w1 w2 w3 w4
                       HS.SockAddrUnix _ -> error "ReCAPTCHA.check"
          req = H.def
                  { H.method      = HT.methodPost
                  , H.host        = "www.google.com"
                  , H.path        = "/recaptcha/api/verify"
                  , H.queryString = HT.renderSimpleQuery False query
                  }
          query = [ ("privatekey", TE.encodeUtf8 privateKey)
                  , ("remoteip",   B8.pack       remoteip)
                  , ("challenge",  TE.encodeUtf8 challenge)
                  , ("response",   TE.encodeUtf8 response)
                  ]
      eresp <- E.try $ C.runResourceT $ H.httpLbs req manager
      case (L8.lines . H.responseBody) <$> eresp of
        Right ("true":_)      -> return Ok
        Right ("false":why:_) -> return . Error . TL.toStrict $
                                 TLE.decodeUtf8With TEE.lenientDecode why
        Right other -> do
          $(YC.logError) $ T.concat [ "Yesod.ReCAPTCHA: could not parse "
                                    , T.pack (show other) ]
          return (Error "recaptcha-not-reachable")
        Left exc -> do
          $(YC.logError) $ T.concat [ "Yesod.ReCAPTCHA: could not contact server ("
                                    , T.pack (show (exc :: E.SomeException))
                                    , ")" ]
          return (Error "recaptcha-not-reachable")


-- | See 'check'.
data CheckRet = Ok | Error T.Text


-- | A fake field.  Just returns the value of a field.
fakeField :: (YC.RenderMessage master YF.FormMessage) =>
             T.Text                   -- ^ Field id.
          -> YC.GWidget sub master () -- ^ Field view.
          -> YF.MForm sub master ( YF.FormResult T.Text
                                 , YF.FieldView sub master )
fakeField fid view = clr <$> YF.mreq YF.textField fs Nothing
    where
      fs = "" { YF.fsId = Just fid }
      clr (fr, fv) = (fr, fv { YF.fvLabel   = ""
                             , YF.fvTooltip = Nothing
                             , YF.fvInput   = view })


-- | Define the given 'RecaptchaOptions' for all forms declared
-- after this widget.  This widget may be used anywhere, on the
-- @<head>@ or on the @<body>@.
recaptchaOptions :: YC.Yesod master =>
                    RecaptchaOptions
                 -> YC.GWidget sub master ()
recaptchaOptions s | s == D.def = return ()
recaptchaOptions s =
  [whamlet|
    <script>
      var RecaptchaOptions = {
      $maybe t <- theme s
        theme : '#{t}',
      $maybe l <- lang s
        lang : '#{l}',
      x : 'x'
      };
    </script>
  |]


-- | Options that may be given to reCAPTCHA.  In order to use
-- them on your site, use `recaptchaOptions` anywhere before the
-- form that contains the `recaptchaField`.
--
-- Note that there's an instance for 'D.Default', so you may use
-- 'D.def'.
data RecaptchaOptions =
  RecaptchaOptions {
      -- | Theme of the reCAPTCHA field.  Currently may be
      -- @\"red\"@, @\"white\"@, @\"blackglass\"@ or @\"clean\"@.
      -- A value of @Nothing@ uses the default.
      theme :: Maybe T.Text

      -- | Language.
    , lang :: Maybe T.Text
    }
  deriving (Eq, Ord, Show, Typeable)

-- | Allows you to use 'D.def' and get sane default values.
instance D.Default RecaptchaOptions where
    def = RecaptchaOptions Nothing Nothing
