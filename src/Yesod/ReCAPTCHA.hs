{-# LANGUAGE DeriveDataTypeable #-}
module Yesod.ReCAPTCHA
    ( recaptchaField
    , recaptchaSettings
    , RecaptchaSettings(..)
    ) where

import Data.Typeable (Typeable)
import qualified Data.Conduit as C
import qualified Data.Default as D
import qualified Data.Text as T
import qualified Network.HTTP.Conduit as H
import qualified Yesod.Core as YC
import qualified Yesod.Form.Types as YF


-- | A reCAPTCHA field.  This 'YF.Field' returns @()@ because
-- CAPTCHAs give no useful information besides having being typed
-- correctly or not.  When the user does not pass the CAPTCHA,
-- this 'YF.Field' will automatically the same way as any other
-- @yesod-form@ widget fails, so you may just ignore the @()@
-- value.
recaptchaField :: YC.Yesod master => YF.Field sub master ()
recaptchaField = undefined


-- | Define the given 'RecaptchaSettings' for all forms declared
-- after the point where this widget is inserted.
recaptchaSettings :: YC.Yesod master => RecaptchaSettings -> YC.GWidget sub master ()
recaptchaSettings = undefined


-- | Settings that may be given to reCAPTCHA.  In order to use
-- them on your site, use `recaptchaSettings` anywhere before the
-- form that contains the `recaptchaField`.
--
-- Note that there's an instance for 'D.Default', so you may use
-- 'D.def'.
data RecaptchaSettings =
  RecaptchaSettings {
      -- | Theme of the reCAPTCHA field.  Currently may be
      -- @\"red\"@, @\"white\"@, @\"blackglass\"@ or @\"clean\"@.
      -- A value of @Nothing@ uses the default.
      theme :: Maybe T.Text

      -- | Language.
    , lang :: Maybe T.Text
    }
  deriving (Eq, Ord, Show, Typeable)

-- | Allows you to use 'D.def' and get sane default values.
instance D.Default RecaptchaSettings where
    def = RecaptchaSettings Nothing Nothing
