module Yesod.ReCAPTCHA
    ( YesodReCAPTCHA(..)
    , recaptchaAForm
    , recaptchaMForm
    , recaptchaOptions
    , RecaptchaOptions(..)
    ) where

import Control.Applicative
import Data.Typeable (Typeable)
import Yesod.Core (whamlet)
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
-- > instance YesodReCAPTCHA MyType where
-- >   recaptchaPublicKey  = return "[your public key]"
-- >   recaptchaPrivateKey = return "[your private key]"
--
-- You may also write a more sophisticated instance.  For
-- example, you may get these values from your @settings.yml@
-- instead of hardcoding them. Or you may give different keys
-- depending on the request (maybe you're serving to two
-- different domains in the same application).
--
-- The 'YA.YesodAuth' superclass is used only for the HTTP
-- request.  Please fill a bug report if you think that this
-- @YesodReCAPTCHA@ may be useful without @YesodAuth@.
--
-- /Minimum complete definition:/ 'recaptchaPublicKey' and
-- 'recaptchaPrivateKey'.
class YA.YesodAuth site => YesodReCAPTCHA site where
    -- | Your reCAPTCHA public key.
    recaptchaPublicKey  :: YC.HandlerT site IO T.Text
    -- | Your reCAPTCHA private key.
    recaptchaPrivateKey :: YC.HandlerT site IO T.Text
    -- | A backdoor to the reCAPTCHA mechanism.  While doing
    -- automated tests you may need to fill a form that is
    -- protected by a CAPTCHA.  The whole point of using a
    -- CAPTCHA is disallowing access to non-humans, which
    -- hopefully your test suite is.
    --
    -- In order to solve this problem, you may define
    --
    -- > insecureRecaptchaBackdoor = return (Just "<secret CAPTCHA>")
    --
    -- Now, whenever someone fills @\<secret CAPTCHA\>@ as the
    -- CAPTCHA, the @yesod-recaptcha@ library will /not/ contact
    -- reCAPTCHA's servers and instead will blindly accept the
    -- secret CAPTCHA.
    --
    -- Note that this is a *huge* security hole in the wrong
    -- hands.  We /do not/ recommend using this function on a
    -- production environment without a good reason.  If for
    -- whatever reason you must use this function on a production
    -- environment, please make use of its access to 'GHandler'
    -- in order to return @Just@ only when strictly necessary.
    -- For example, you may return @Just@ only when the request
    -- comes from @localhost@ and read its contents from a secret
    -- file accessible only by SSH which is afterwards removed.
    --
    -- By default, this function returns @Nothing@, which
    -- completely disables the backdoor.
    insecureRecaptchaBackdoor :: YC.HandlerT site IO (Maybe T.Text)
    insecureRecaptchaBackdoor = return Nothing


-- | A reCAPTCHA field.  This 'YF.AForm' returns @()@ because
-- CAPTCHAs give no useful information besides having being typed
-- correctly or not.  When the user does not type the CAPTCHA
-- correctly, this 'YF.AForm' will automatically fail in the same
-- way as any other @yesod-form@ widget fails, so you may just
-- ignore the @()@ value.
recaptchaAForm :: YesodReCAPTCHA site => YF.AForm (YC.HandlerT site IO) ()
recaptchaAForm = YF.formToAForm recaptchaMForm


-- | Same as 'recaptchaAForm', but instead of being an
-- 'YF.AForm', it's an 'YF.MForm'.
recaptchaMForm :: YesodReCAPTCHA site =>
                  YF.MForm (YC.HandlerT site IO)
                           ( YF.FormResult ()
                           , [YF.FieldView site] )
recaptchaMForm = do
  challengeField <- fakeField "recaptcha_challenge_field"
  responseField  <- fakeField "recaptcha_response_field"
  ret <- maybe (return Nothing)
               (YC.lift . fmap Just . uncurry check)
               ((,) <$> challengeField <*> responseField)
  let view = recaptchaWidget $ case ret of
                                 Just (Error err) -> Just err
                                 _                -> Nothing
      formRet = case ret of
                  Nothing        -> YF.FormMissing
                  Just Ok        -> YF.FormSuccess ()
                  Just (Error _) -> YF.FormFailure []
      formView = YF.FieldView
                   { YF.fvLabel    = ""
                   , YF.fvTooltip  = Nothing
                   , YF.fvId       = "recaptcha_challenge_field"
                   , YF.fvInput    = view
                   , YF.fvErrors   = Nothing
                   , YF.fvRequired = True
                   }
  return (formRet, [formView])


-- | Widget with reCAPTCHA's HTML.
recaptchaWidget :: YesodReCAPTCHA site =>
                   Maybe T.Text -- ^ Error code, if any.
                -> YC.WidgetT site IO ()
recaptchaWidget merr = do
  publicKey <- YC.handlerToWidget recaptchaPublicKey
  isSecure  <- W.isSecure <$> YC.waiRequest
  let proto | isSecure  = "https"
            | otherwise = "http" :: T.Text
      err = maybe "" (T.append "&error=") merr
  [whamlet|
    <script src="#{proto}://www.google.com/recaptcha/api/challenge?k=#{publicKey}#{err}">
    <noscript>
       <iframe src="#{proto}://www.google.com/recaptcha/api/noscript?k=#{publicKey}#{err}"
           height="300" width="500" frameborder="0">
       <br>
       <textarea name="recaptcha_challenge_field" rows="3" cols="40">
       <input type="hidden" name="recaptcha_response_field" value="manual_challenge">
  |]


-- | Contact reCAPTCHA servers and find out if the user correctly
-- guessed the CAPTCHA.  Unfortunately, reCAPTCHA doesn't seem to
-- provide an HTTPS endpoint for this API even though we need to
-- send our private key.
check :: YesodReCAPTCHA site =>
         T.Text -- ^ @recaptcha_challenge_field@
      -> T.Text -- ^ @recaptcha_response_field@
      -> YC.HandlerT site IO CheckRet
check "" _ = return $ Error "invalid-request-cookie"
check _ "" = return $ Error "incorrect-captcha-sol"
check challenge response = do
  backdoor <- insecureRecaptchaBackdoor
  if Just response == backdoor
    then return Ok
    else do
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
              req = D.def
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
fakeField :: (YC.RenderMessage site YF.FormMessage) =>
             T.Text -- ^ Field id.
          -> YF.MForm (YC.HandlerT site IO) (Maybe T.Text)
fakeField fid = YC.lift $ do mt1 <- YC.lookupGetParam fid
                             case mt1 of
                               Nothing -> YC.lookupPostParam fid
                               Just _  -> return mt1


-- | Define the given 'RecaptchaOptions' for all forms declared
-- after this widget.  This widget may be used anywhere, on the
-- @<head>@ or on the @<body>@.
--
-- Note that this is /not/ required to use 'recaptchaAForm' or
-- 'recaptchaMForm'.
recaptchaOptions :: YC.Yesod site =>
                    RecaptchaOptions
                 -> YC.WidgetT site IO ()
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
