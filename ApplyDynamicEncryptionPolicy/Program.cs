using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Linq;
using Microsoft.WindowsAzure.MediaServices.Client;
using Microsoft.WindowsAzure.MediaServices.Client.ContentKeyAuthorization;
using Microsoft.WindowsAzure.MediaServices.Client.DynamicEncryption;
using Microsoft.WindowsAzure.MediaServices.Client.Widevine;
using Microsoft.WindowsAzure.MediaServices.Client.FairPlay;
using Newtonsoft.Json;
using System.Security.Cryptography.X509Certificates;

namespace ApplyDynamicEncryptionPolicy
{
    class Program
    {
        // Read values from the App.config file.
        private static readonly string _mediaServicesAccountName =
            ConfigurationManager.AppSettings["MediaServicesAccountName"];
        private static readonly string _mediaServicesAccountKey =
            ConfigurationManager.AppSettings["MediaServicesAccountKey"];

        private static readonly bool _isTokenRestricted =
            Convert.ToBoolean(ConfigurationManager.AppSettings["IsTokenRestricted"]);

        private static readonly string _authPolicyNameContentKeyCommon =
            ConfigurationManager.AppSettings["AuthPolicyWithNameContentKeyCommon"];
        private static readonly string _authPolicyNameContentKeyCommonCBC =
            ConfigurationManager.AppSettings["AuthPolicyWithNameContentKeyCommonCBC"];

        private static readonly bool _isTokenTypeJWT =
            Convert.ToBoolean(ConfigurationManager.AppSettings["IsTokenTypeJWT"]);
        private static readonly Uri _sampleIssuer =
            new Uri(ConfigurationManager.AppSettings["TokenIssuer"]);
        private static readonly Uri _sampleAudience =
            new Uri(ConfigurationManager.AppSettings["TokenAudience"]);
        private static readonly string _symmetricVerificationKey =
            ConfigurationManager.AppSettings["TokenVerifySymKeyB64"];
        private static readonly bool _enableKidClaim =
            Convert.ToBoolean(ConfigurationManager.AppSettings["EnableKidClaim"]);

        private static readonly string _fairplayASK =
            ConfigurationManager.AppSettings["FairPlayASK"];
        private static readonly string _fairplayAppCert =
            ConfigurationManager.AppSettings["FairPlayAppCertFile"];
        private static readonly string _fairplayAppCertPassword =
            ConfigurationManager.AppSettings["FairPlayAppCertPassword"];

        // Field for service context.
        private static CloudMediaContext _context = null;
        private static MediaServicesCredentials _cachedCredentials = null;

        private static readonly string _dataFolder =
            Path.GetFullPath(@"../..\Data");

        private enum Ops {
            None,
            ListAll,
            ListContentKey,
            ListAuthPolicy,
            ListAuthPolicyOption,
            RemoveContentKey,
            RemoveAuthPolicy,
            RemoveAuthPolicyOption,
            CreateDrmAuthPolicy,
            DeleteDrmAuthPolicy,
            RegisterDrmAuthPolicyToAsset,
            UnregisterDrmAuthPolicyToAsset
        }

        static void Main(string[] args)
        {
            Ops op = Ops.None;
            List<String> idList = GetOptions(args, ref op);
            // Create and cache the Media Services credentials in a static class variable.
            _cachedCredentials = new MediaServicesCredentials(_mediaServicesAccountName, _mediaServicesAccountKey);
            // Used the cached credentials to create CloudMediaContext.
            _context = new CloudMediaContext(_cachedCredentials);

            switch (op)
            {
                case Ops.ListAll:
                    ListContentKey();
                    ListContentKeyAuthorizationPolicy();
                    ListContentKeyAuthorizationPolicyOptions();
                    break;
                case Ops.ListContentKey:
                    ListContentKey();
                    break;
                case Ops.ListAuthPolicy:
                    ListContentKeyAuthorizationPolicy();
                    break;
                case Ops.ListAuthPolicyOption:
                    ListContentKeyAuthorizationPolicyOptions();
                    break;
                case Ops.RemoveContentKey:
                    foreach (var id in idList) RemoveContentKey(id);
                    break;
                case Ops.RemoveAuthPolicy:
                    foreach (var id in idList) RemoveContentKeyAuthorizationPolicy(id);
                    break;
                case Ops.RemoveAuthPolicyOption:
                    foreach (var id in idList) RemoveContentKeyAuthorizationPolicyOption(id);
                    break;
                case Ops.CreateDrmAuthPolicy:
                    CreateMultiDrmAuthorizationPolicy();
                    break;
                case Ops.DeleteDrmAuthPolicy:
                    DeleteMultiDrmAuthorizationPolicy();
                    break;
                case Ops.RegisterDrmAuthPolicyToAsset:
                    foreach (var id in idList) ApplyMultiDrmAuthorizationPolicyToAsset(id);
                    break;
                case Ops.UnregisterDrmAuthPolicyToAsset:
                    foreach (var id in idList) DeleteMultiDrmAuthorizationPolicyToAsset(id);
                    break;
                default:
                    PrintHelp();
                    break;
            }
            Console.WriteLine("\nPress any key...");
            Console.ReadLine();
            return;
        }

        static public void ListContentKey()
        {
            Console.WriteLine("ContentKey List:");
            foreach (var contentKey in _context.ContentKeys)
            {
                Console.WriteLine("  {0} = {1} [{2}] - [{3}]", contentKey.Id, contentKey.Name, contentKey.ContentKeyType, contentKey.Created);
            }

        }
        static public void ListContentKeyAuthorizationPolicy()
        {
            Console.WriteLine("ContentKeyAuthorizationPolicy List:");
            foreach (IContentKeyAuthorizationPolicy policy in _context.ContentKeyAuthorizationPolicies)
            {
                Console.WriteLine("  {0} = {1}", policy.Id, policy.Name);
            }

        }
        static public void ListContentKeyAuthorizationPolicyOptions()
        {
            Console.WriteLine("ContentKeyAuthorizationPolicyOptions List:");
            foreach (var policyOptions in _context.ContentKeyAuthorizationPolicyOptions)
            {
                Console.WriteLine("  {0} = {1}", policyOptions.Id, policyOptions.Name);
            }

        }

        public static void RemoveContentKey(string id)
        {
            IContentKey contentKey = _context.ContentKeys.Where(p => p.Id == id).FirstOrDefault();
            if (contentKey != null)
            {
                try
                {
                    string keyId = contentKey.Id;
                    string keyName = contentKey.Name;
                    contentKey.Delete();
                    Console.WriteLine("Deleted Content Key {0} : {1}", keyId, keyName);
                }
                catch (Exception e)
                {
                    Console.WriteLine("Error on deleting Content Key {0} : {1}", id, e.ToString());
                }
            }
            else
            {
                Console.WriteLine("Error: Content Key {0} Not Found", id);
            }
            return;
        }
        public static void RemoveContentKeyAuthorizationPolicy(string id)
        {
            IContentKeyAuthorizationPolicy policy = _context.ContentKeyAuthorizationPolicies.Where(p => p.Id == id).FirstOrDefault();
            if (policy != null)
            {
                try
                {
                    string pId = policy.Id;
                    string pName = policy.Name;
                    if (_context.ContentKeys.Where(p => p.AuthorizationPolicyId == pId).Count() != 0)
                    {
                        Console.WriteLine("ContentKey associated : Not deleting ContentKey Authorization Policy {0} : {1}", pId, pName);
                        return;
                    }
                    List<IContentKeyAuthorizationPolicyOption> options = new List<IContentKeyAuthorizationPolicyOption>(policy.Options);
                    policy.Delete();
                    Console.WriteLine("Deleted ContentKey Authorization Policy {0} : {1}", pId, pName);
                    foreach (IContentKeyAuthorizationPolicyOption option in options)
                    {
                        RemoveContentKeyAuthorizationPolicyOption(option.Id);
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine("Error on deleting ContentKey Authorization Policy {0} : {1}", id, e.ToString());
                }
            }
            else
            {
                Console.WriteLine("Error: ContentKey Authorization Policy {0} Not Found", id);
            }
            return;
        }
        public static void RemoveContentKeyAuthorizationPolicyOption(string id)
        {
            IContentKeyAuthorizationPolicyOption option = _context.ContentKeyAuthorizationPolicyOptions.Where(p => p.Id == id).FirstOrDefault();
            if (option != null)
            {
                try
                {
                    string oId = option.Id;
                    string oName = option.Name;
                    if (option.KeyDeliveryType == ContentKeyDeliveryType.FairPlay)
                    {
                        dynamic data = JsonConvert.DeserializeObject(option.KeyDeliveryConfiguration);
                        string contentKeyASkId = "nb:kid:UUID:" + data.ASkId;
                        string contentKeyFairPlayPfxPasswordId = "nb:kid:UUID:" + data.FairPlayPfxPasswordId;
                        RemoveContentKey(contentKeyASkId);
                        RemoveContentKey(contentKeyFairPlayPfxPasswordId);
                    }
                    option.Delete();
                    Console.WriteLine("Deleted ContentKey Authorization Policy Option {0} : {1}", oId, oName);
                }
                catch (Exception e)
                {
                    Console.WriteLine("Error on deleting ContentKey Authorization Policy Option {0} : {1}", id, e.ToString());
                }
            }
            else
            {
                Console.WriteLine("Error: ContentKey Authorization Policy Option {0} Not Found", id);
            }
            return;
        }


        public static IContentKeyAuthorizationPolicy CreateMultiDrmAuthorizationPolicyCommonType()
        {
            // ContentKeyType.CommonEncryption
            IContentKeyAuthorizationPolicy pol =
                _context.ContentKeyAuthorizationPolicies.Where(p => p.Name == _authPolicyNameContentKeyCommon).FirstOrDefault();
            if (pol != null)
            {
                Console.WriteLine("Already exist Token Restricted CENC Type Policy: Id = {0}, Name = {1}", pol.Id, pol.Name);
                return pol;
            }
            pol = CreateAuthorizationPolicyCommonType(_authPolicyNameContentKeyCommon);
            Console.WriteLine("Created Token Restricted CENC Type Policy: Id = {0}, Name = {1}", pol.Id, pol.Name);
            return pol;
        }
        public static IContentKeyAuthorizationPolicy CreateMultiDrmAuthorizationPolicyCommonCBCType()
        {
            // ContentKeyType.CommonEncryptionCbcs
            IContentKeyAuthorizationPolicy pol =
                _context.ContentKeyAuthorizationPolicies.Where(p => p.Name == _authPolicyNameContentKeyCommonCBC).FirstOrDefault();
            if (pol != null)
            {
                Console.WriteLine("Already exist Token Restricted CENC cbcs Type Policy: Id = {0}, Name = {1}", pol.Id, pol.Name);
                return pol;
            }
            pol = CreateAuthorizationPolicyCommonCBCType(_authPolicyNameContentKeyCommonCBC);
            Console.WriteLine("Created Token Restricted CENC cbcs Type Policy: Id = {0}, Name = {1}", pol.Id, pol.Name);
            return pol;
        }
        public static void CreateMultiDrmAuthorizationPolicy()
        {
            CreateMultiDrmAuthorizationPolicyCommonType();
            CreateMultiDrmAuthorizationPolicyCommonCBCType();
        }
        public static void DeleteMultiDrmAuthorizationPolicy()
        {
            // ContentKeyType.CommonEncryption
            IContentKeyAuthorizationPolicy polCommon =
                _context.ContentKeyAuthorizationPolicies.Where(p => p.Name == _authPolicyNameContentKeyCommon).FirstOrDefault();
            if (polCommon != null)
            {
                RemoveContentKeyAuthorizationPolicy(polCommon.Id);
            }
            // ContentKeyType.CommonEncryptionCbcs
            IContentKeyAuthorizationPolicy polCommonCBC =
                _context.ContentKeyAuthorizationPolicies.Where(p => p.Name == _authPolicyNameContentKeyCommon).FirstOrDefault();
            if (polCommonCBC != null)
            {
                RemoveContentKeyAuthorizationPolicy(polCommonCBC.Id);
            }

        }
        public static void ApplyMultiDrmAuthorizationPolicyToAsset(string id)
        {
            IAsset asset = _context.Assets.Where(a => a.Id == id).FirstOrDefault();
            if (asset == null)
            {
                Console.WriteLine("Error: Asset {0} Not Found", id);
            }
            else
            {
                System.Console.WriteLine("Asset Name = {0}", asset.Name);
                DeleteMultiDrmAuthorizationPolicyToAsset(id);

                IContentKey keyCENC = CreateContentKeyCommonType(asset);
                Console.WriteLine("Created CENC key {0} for the asset {1} ", keyCENC.Id, asset.Id);
                Console.WriteLine("PlayReady License Key delivery URL: {0}", keyCENC.GetKeyDeliveryUrl(ContentKeyDeliveryType.PlayReadyLicense));
                Console.WriteLine("Widevine License Key delivery URL: {0}", keyCENC.GetKeyDeliveryUrl(ContentKeyDeliveryType.Widevine));
                IContentKey keyCENCcbcs = CreateContentKeyCommonCBCType(asset);
                Console.WriteLine("Created CENC-cbcs key {0} for the asset {1} ", keyCENCcbcs.Id, asset.Id);
                Console.WriteLine("FairPlay License Key delivery URL: {0}", keyCENCcbcs.GetKeyDeliveryUrl(ContentKeyDeliveryType.FairPlay));
                Console.WriteLine();

                IContentKeyAuthorizationPolicy policyCENC = CreateMultiDrmAuthorizationPolicyCommonType();                
                keyCENC.AuthorizationPolicyId = policyCENC.Id;
                keyCENC = keyCENC.UpdateAsync().Result;
                Console.WriteLine("Added authorization policy to CENC Key: {0}", keyCENC.AuthorizationPolicyId);

                IContentKeyAuthorizationPolicy policyCENCcbcs = CreateMultiDrmAuthorizationPolicyCommonCBCType();
                keyCENCcbcs.AuthorizationPolicyId = policyCENCcbcs.Id;
                keyCENCcbcs = keyCENCcbcs.UpdateAsync().Result;
                Console.WriteLine("Added authorization policy to CENC-cbcs Key: {0}", keyCENCcbcs.AuthorizationPolicyId);
                Console.WriteLine();

                CreateAssetDeliveryPolicyCenc(asset, keyCENC);
                CreateAssetDeliveryPolicyCencCbcs(asset, keyCENCcbcs);
                Console.WriteLine("Created asset delivery policy.\n");

                string url = GetStreamingOriginLocator(asset);
                Console.WriteLine("Created locator.");
                Console.WriteLine("Encrypted Smooth+PlayReady URL: {0}/manifest", url);
                Console.WriteLine("Encrypted MPEG-DASH URL: {0}/manifest(format=mpd-time-csf)", url);
                Console.WriteLine("Encrypted HLS+FairPlay URL: {0}/manifest(format=m3u8-aapl)", url);
            }

        }
        public static void DeleteMultiDrmAuthorizationPolicyToAsset(string id)
        {
            IAsset asset = _context.Assets.Where(a => a.Id == id).FirstOrDefault();
            if (asset == null)
            {
                Console.WriteLine("Error: Asset {0} Not Found", id);
            }
            else
            {
                System.Console.WriteLine("Asset Name = {0}", asset.Name);
                // Delete Locators
                List<ILocator> locators = new List<ILocator>(asset.Locators);
                foreach (var loc in locators)
                {
                    string locId = loc.Id;
                    string locName = loc.Name;
                    loc.Delete();
                    Console.WriteLine("Removed Delivery Policy ({0} = {1}) from Asset {0}", locId, locName, id);
                }
                // Delete AssetDeliveryPolicies
                List<IAssetDeliveryPolicy> assetDeliveryPolicies = new List<IAssetDeliveryPolicy>(asset.DeliveryPolicies);
                foreach (var assetDeliveryPolicy in assetDeliveryPolicies)
                {
                    asset.DeliveryPolicies.Remove(assetDeliveryPolicy);
                    Console.WriteLine("Removed Delivery Policy ({0} = {1}) from Asset {0}", assetDeliveryPolicy.Id, assetDeliveryPolicy.Name, id);
                }
                List<IContentKey> keys = new List<IContentKey>(asset.ContentKeys);
                foreach (var key in keys)
                {
                    if (key.ContentKeyType != ContentKeyType.StorageEncryption)
                    {
                        asset.ContentKeys.Remove(key);
                        Console.WriteLine("Removed Content Key ({0} = {1}) from Asset {0}", key.Id, key.Name, id);
                    }
                }
            }
        }

        static public IContentKey CreateContentKeyCommonType(IAsset asset)
        {

            Guid keyId = Guid.NewGuid();
            byte[] contentKey = GetRandomBuffer(16);

            IContentKey key = _context.ContentKeys.Create(
                                    keyId,
                                    contentKey,
                                    "ContentKey CENC",
                                    ContentKeyType.CommonEncryption);

            // Associate the key with the asset.
            asset.ContentKeys.Add(key);

            return key;
        }
        static public IContentKey CreateContentKeyCommonCBCType(IAsset asset)
        {
            // Create HLS SAMPLE AES encryption content key
            Guid keyId = Guid.NewGuid();
            byte[] contentKey = GetRandomBuffer(16);

            IContentKey key = _context.ContentKeys.Create(
                                    keyId,
                                    contentKey,
                                    "ContentKey CENC cbcs",
                                    ContentKeyType.CommonEncryptionCbcs);

            // Associate the key with the asset.
            asset.ContentKeys.Add(key);

            return key;
        }
        static public IContentKeyAuthorizationPolicy CreateAuthorizationPolicyCommonType(string policyName)
        {
            List<ContentKeyAuthorizationPolicyRestriction> restrictions;
            string PlayReadyOptionName;
            string WidevineOptionName;
            if (_isTokenRestricted)
            {
                string tokenTemplateString = GenerateTokenRequirements();
                restrictions = new List<ContentKeyAuthorizationPolicyRestriction>
                {
                    new ContentKeyAuthorizationPolicyRestriction
                    {
                        Name = "Token Authorization Policy",
                        KeyRestrictionType = (int)ContentKeyRestrictionType.TokenRestricted,
                        Requirements = tokenTemplateString,
                    }
                };
                PlayReadyOptionName = "TokenRestricted PlayReady Option 1";
                WidevineOptionName = "TokenRestricted Widevine Option 1";
            }
            else
            {
                restrictions = new List<ContentKeyAuthorizationPolicyRestriction>
                {
                    new ContentKeyAuthorizationPolicyRestriction
                    {
                        Name = "Open",
                        KeyRestrictionType = (int)ContentKeyRestrictionType.Open,
                        Requirements = null
                    }
                };
                PlayReadyOptionName = "Open PlayReady Option 1";
                WidevineOptionName = "Open Widevine Option 1";
            }

            // Configure PlayReady and Widevine license templates.
            string PlayReadyLicenseTemplate = ConfigurePlayReadyPolicyOptions();
            string WidevineLicenseTemplate = ConfigureWidevinePolicyOptions();

            IContentKeyAuthorizationPolicyOption PlayReadyPolicy =
                _context.ContentKeyAuthorizationPolicyOptions.Create(PlayReadyOptionName, ContentKeyDeliveryType.PlayReadyLicense, restrictions, PlayReadyLicenseTemplate);
            IContentKeyAuthorizationPolicyOption WidevinePolicy =
                _context.ContentKeyAuthorizationPolicyOptions.Create(WidevineOptionName, ContentKeyDeliveryType.Widevine, restrictions, WidevineLicenseTemplate);
            IContentKeyAuthorizationPolicy contentKeyAuthorizationPolicy = _context.ContentKeyAuthorizationPolicies.CreateAsync(policyName).Result;

            contentKeyAuthorizationPolicy.Options.Add(PlayReadyPolicy);
            contentKeyAuthorizationPolicy.Options.Add(WidevinePolicy);

            return contentKeyAuthorizationPolicy;
        }
        static public IContentKeyAuthorizationPolicy CreateAuthorizationPolicyCommonCBCType(string policyName)
        {
            List<ContentKeyAuthorizationPolicyRestriction> restrictions;
            string FairPlayOptionName;
            if (_isTokenRestricted)
            {
                string tokenTemplateString = GenerateTokenRequirements();
                restrictions = new List<ContentKeyAuthorizationPolicyRestriction>
                        {
                            new ContentKeyAuthorizationPolicyRestriction
                            {
                                Name = "Token Authorization Policy",
                                KeyRestrictionType = (int)ContentKeyRestrictionType.TokenRestricted,
                                Requirements = tokenTemplateString,
                            }
                        };
                FairPlayOptionName = "TokenRestricted FairPlay Option 1";
            }
            else
            {
                restrictions = new List<ContentKeyAuthorizationPolicyRestriction>
                        {
                            new ContentKeyAuthorizationPolicyRestriction
                            {
                                Name = "Open",
                                KeyRestrictionType = (int)ContentKeyRestrictionType.Open,
                                Requirements = null
                            }
                        };
                FairPlayOptionName = "Open FairPlay Option 1";
            }

            // Configure FairPlay policy option.
            string FairPlayConfiguration = ConfigureFairPlayPolicyOptions();

            IContentKeyAuthorizationPolicyOption FairPlayPolicy =
                _context.ContentKeyAuthorizationPolicyOptions.Create(FairPlayOptionName, ContentKeyDeliveryType.FairPlay, restrictions, FairPlayConfiguration);
            IContentKeyAuthorizationPolicy contentKeyAuthorizationPolicy = _context.ContentKeyAuthorizationPolicies.CreateAsync(policyName).Result;

            contentKeyAuthorizationPolicy.Options.Add(FairPlayPolicy);

            return contentKeyAuthorizationPolicy;
        }


        private static string ConfigurePlayReadyPolicyOptions()
        {
            // The following code configures PlayReady License Template using .NET classes
            // and returns the XML string.

            //The PlayReadyLicenseResponseTemplate class represents the template for the response sent back to the end user.
            //It contains a field for a custom data string between the license server and the application
            //(may be useful for custom app logic) as well as a list of one or more license templates.
            PlayReadyLicenseResponseTemplate responseTemplate = new PlayReadyLicenseResponseTemplate();

            // The PlayReadyLicenseTemplate class represents a license template for creating PlayReady licenses
            // to be returned to the end users.
            //It contains the data on the content key in the license and any rights or restrictions to be
            //enforced by the PlayReady DRM runtime when using the content key.
            PlayReadyLicenseTemplate licenseTemplate = new PlayReadyLicenseTemplate();
            //Configure whether the license is persistent (saved in persistent storage on the client)
            //or non-persistent (only held in memory while the player is using the license).  
            licenseTemplate.LicenseType = PlayReadyLicenseType.Nonpersistent;

            // AllowTestDevices controls whether test devices can use the license or not.  
            // If true, the MinimumSecurityLevel property of the license
            // is set to 150.  If false (the default), the MinimumSecurityLevel property of the license is set to 2000.
            licenseTemplate.AllowTestDevices = false;

            // You can also configure the Play Right in the PlayReady license by using the PlayReadyPlayRight class.
            // It grants the user the ability to playback the content subject to the zero or more restrictions
            // configured in the license and on the PlayRight itself (for playback specific policy).
            // Much of the policy on the PlayRight has to do with output restrictions
            // which control the types of outputs that the content can be played over and
            // any restrictions that must be put in place when using a given output.
            // For example, if the DigitalVideoOnlyContentRestriction is enabled,
            //then the DRM runtime will only allow the video to be displayed over digital outputs
            //(analog video outputs won’t be allowed to pass the content).

            //IMPORTANT: These types of restrictions can be very powerful but can also affect the consumer experience.
            // If the output protections are configured too restrictive,
            // the content might be unplayable on some clients. For more information, see the PlayReady Compliance Rules document.

            // For example:
            //licenseTemplate.PlayRight.AgcAndColorStripeRestriction = new AgcAndColorStripeRestriction(1);

            responseTemplate.LicenseTemplates.Add(licenseTemplate);

            return MediaServicesLicenseTemplateSerializer.Serialize(responseTemplate);
        }
        private static string ConfigureWidevinePolicyOptions()
        {
            var template = new WidevineMessage
            {
                allowed_track_types = AllowedTrackTypes.SD_HD,
                content_key_specs = new[]
                {
                    new ContentKeySpecs
                    {
                        required_output_protection = new RequiredOutputProtection { hdcp = Hdcp.HDCP_NONE},
                        security_level = 1,
                        track_type = "SD"
                    }
                },
                policy_overrides = new
                {
                    can_play = true,
                    can_persist = true,
                    can_renew = false
                    //renewal_server_url = keyDeliveryUrl.ToString(),
                }
            };

            string configuration = JsonConvert.SerializeObject(template);
            return configuration;
        }
        private static string ConfigureFairPlayPolicyOptions()
        {
            // For testing you can provide all zeroes for ASK bytes together with the cert from Apple FPS SDK.
            // However, for production you must use a real ASK from Apple bound to a real prod certificate.
            byte[] askBytes = ConvertHexStringToByte(_fairplayASK, 16);
            if (askBytes == null) throw new Exception("Bad ASK parameter.");
            var askId = Guid.NewGuid();
            // Key delivery retrieves askKey by askId and uses this key to generate the response.
            IContentKey askKey = _context.ContentKeys.Create(
                                    askId,
                                    askBytes,
                                    "FairPlay AppSecret (ASK)",
                                    ContentKeyType.FairPlayASk);

            //Customer password for creating the .pfx file.
            string pfxPassword = _fairplayAppCertPassword;
            // Key delivery retrieves pfxPasswordKey by pfxPasswordId and uses this key to generate the response.
            var pfxPasswordId = Guid.NewGuid();
            byte[] pfxPasswordBytes = System.Text.Encoding.UTF8.GetBytes(pfxPassword);
            IContentKey pfxPasswordKey = _context.ContentKeys.Create(
                                    pfxPasswordId,
                                    pfxPasswordBytes,
                                    "FairPlay AppCert PfxPasswordKey",
                                    ContentKeyType.FairPlayPfxPassword);

            // iv - 16 bytes random value, must match the iv in the asset delivery policy.
            byte[] iv = Guid.NewGuid().ToByteArray();

            //Specify the .pfx file created by the customer.
            var appCert = new X509Certificate2(Path.Combine(_dataFolder, _fairplayAppCert), pfxPassword, X509KeyStorageFlags.Exportable);

            string FairPlayConfiguration =
                Microsoft.WindowsAzure.MediaServices.Client.FairPlay.FairPlayConfiguration.CreateSerializedFairPlayOptionConfiguration(
                    appCert,
                    pfxPassword,
                    pfxPasswordId,
                    askId,
                    iv);

            return FairPlayConfiguration;
        }
        private static string GenerateTokenRequirements()
        {
            TokenType tType = TokenType.SWT;
            if (_isTokenTypeJWT) tType = TokenType.JWT;
            TokenRestrictionTemplate template = new TokenRestrictionTemplate(tType);
            template.PrimaryVerificationKey = new SymmetricVerificationKey(Convert.FromBase64String(_symmetricVerificationKey));
            //template.AlternateVerificationKeys.Add(new SymmetricVerificationKey());
            template.Audience = _sampleAudience.ToString();
            template.Issuer = _sampleIssuer.ToString();
            if (_enableKidClaim)
                template.RequiredClaims.Add(TokenClaim.ContentKeyIdentifierClaim);
            return TokenRestrictionTemplateSerializer.Serialize(template);
        }
        private static byte[] ConvertHexStringToByte(string hexString, int byteLength)
        {
            // Check inputs
            if (byteLength <= 0) return null;
            if (hexString.Length != byteLength * 2) return null;
            return Enumerable.Range(0, hexString.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hexString.Substring(x, 2), 16))
                             .ToArray();
        }



        static public void CreateAssetDeliveryPolicyCenc(IAsset asset, IContentKey key)
        {
            // Get the PlayReady license service URL.
            Uri acquisitionUrl = key.GetKeyDeliveryUrl(ContentKeyDeliveryType.PlayReadyLicense);

            // GetKeyDeliveryUrl for Widevine attaches the KID to the URL.
            // For example: https://amsaccount1.keydelivery.mediaservices.windows.net/Widevine/?KID=268a6dcb-18c8-4648-8c95-f46429e4927c.  
            // The WidevineBaseLicenseAcquisitionUrl (used below) also tells Dynamaic Encryption
            // to append /? KID =< keyId > to the end of the url when creating the manifest.
            // As a result Widevine license acquisition URL will have KID appended twice,
            // so we need to remove the KID that in the URL when we call GetKeyDeliveryUrl.

            Uri widevineUrl = key.GetKeyDeliveryUrl(ContentKeyDeliveryType.Widevine);
            UriBuilder uriBuilder = new UriBuilder(widevineUrl);
            uriBuilder.Query = String.Empty;
            widevineUrl = uriBuilder.Uri;

            Dictionary<AssetDeliveryPolicyConfigurationKey, string> assetDeliveryPolicyConfiguration =
                new Dictionary<AssetDeliveryPolicyConfigurationKey, string>
                {
                        {AssetDeliveryPolicyConfigurationKey.PlayReadyLicenseAcquisitionUrl, acquisitionUrl.ToString()},
                        {AssetDeliveryPolicyConfigurationKey.WidevineBaseLicenseAcquisitionUrl, widevineUrl.ToString()}

                };

            // In this case we only specify Dash streaming protocol in the delivery policy,
            // All other protocols will be blocked from streaming.
            var assetDeliveryPolicy = _context.AssetDeliveryPolicies.Create(
                    "AssetDeliveryPolicy CommonEncryption (SmoothStreaming, Dash)",
                AssetDeliveryPolicyType.DynamicCommonEncryption,
                AssetDeliveryProtocol.Dash | AssetDeliveryProtocol.SmoothStreaming,
                assetDeliveryPolicyConfiguration);


            // Add AssetDelivery Policy to the asset
            asset.DeliveryPolicies.Add(assetDeliveryPolicy);
        }
        static public void CreateAssetDeliveryPolicyCencCbcs(IAsset asset, IContentKey key)
        {
            var kdPolicy = _context.ContentKeyAuthorizationPolicies.Where(p => p.Id == key.AuthorizationPolicyId).Single();

            var kdOption = kdPolicy.Options.Single(o => o.KeyDeliveryType == ContentKeyDeliveryType.FairPlay);

            FairPlayConfiguration configFP = JsonConvert.DeserializeObject<FairPlayConfiguration>(kdOption.KeyDeliveryConfiguration);

            // Get the FairPlay license service URL.
            Uri acquisitionUrl = key.GetKeyDeliveryUrl(ContentKeyDeliveryType.FairPlay);

            // The reason the below code replaces "https://" with "skd://" is because
            // in the IOS player sample code which you obtained in Apple developer account,
            // the player only recognizes a Key URL that starts with skd://.
            // However, if you are using a customized player,
            // you can choose whatever protocol you want.
            // For example, "https".

            Dictionary<AssetDeliveryPolicyConfigurationKey, string> assetDeliveryPolicyConfiguration =
                new Dictionary<AssetDeliveryPolicyConfigurationKey, string>
                {
                        {AssetDeliveryPolicyConfigurationKey.FairPlayLicenseAcquisitionUrl, acquisitionUrl.ToString().Replace("https://", "skd://")},
                        {AssetDeliveryPolicyConfigurationKey.CommonEncryptionIVForCbcs, configFP.ContentEncryptionIV}
                };

            var assetDeliveryPolicy = _context.AssetDeliveryPolicies.Create(
                    "AssetDeliveryPolicy CommonEncryptionCbcs (HLS)",
                AssetDeliveryPolicyType.DynamicCommonEncryptionCbcs,
                AssetDeliveryProtocol.HLS,
                assetDeliveryPolicyConfiguration);

            // Add AssetDelivery Policy to the asset
            asset.DeliveryPolicies.Add(assetDeliveryPolicy);
        }

        static public string GetStreamingOriginLocator(IAsset asset)
        {

            // Get a reference to the streaming manifest file from the  
            // collection of files in the asset.

            var assetFile = asset.AssetFiles.Where(f => f.Name.ToLower().
                                         EndsWith(".ism")).
                                         FirstOrDefault();

            // Create a 30-day readonly access policy.
            IAccessPolicy policy = _context.AccessPolicies.Create("Streaming policy",
                TimeSpan.FromDays(30),
                AccessPermissions.Read);

            // Create a locator to the streaming content on an origin.
            ILocator originLocator = _context.Locators.CreateLocator(LocatorType.OnDemandOrigin, asset,
                policy,
                DateTime.UtcNow.AddMinutes(-5));

            // Create a URL to the manifest file.
            return originLocator.Path + assetFile.Name;
        }

        static private byte[] GetRandomBuffer(int length)
        {
            var returnValue = new byte[length];

            using (var rng =
                new System.Security.Cryptography.RNGCryptoServiceProvider())
            {
                rng.GetBytes(returnValue);
            }

            return returnValue;
        }

        static private void PrintHelp()
        {
            Console.WriteLine("Azure Media Services - Dynamic Encryption Policy Configuration Tool\n");
            Console.WriteLine("ApplyDynamicEncryptionPolicy.exe operation [operation args]\n");
            Console.WriteLine("operation:");
            Console.WriteLine("    --createdrmauthpolicy:        Create ContentKeyAuthorizationPolicy");
            Console.WriteLine("    --deletedrmauthpolicy:        Remove ContentKeyAuthorizationPolicy");
            Console.WriteLine("    --applydrmauthpolicytoasset <assetId> [<assetId> ...]:");
            Console.WriteLine("                                  Apply ContentKeyAuthorizationPolicy to an asset");
            Console.WriteLine("");
            Console.WriteLine("    --listcontentkey:                List ContentKey");
            Console.WriteLine("    --listauthpolicy:                List ContentKeyAuthorizationPolicy");
            Console.WriteLine("    --listauthpolicyoption:          List ContentKeyAuthorizationPolicyOption");
            Console.WriteLine("    --listall:                       List ContentKey, AuthorizationPolicy, and AuthorizationPolicyOption");
            Console.WriteLine("    --removecontentkey: <KId>        Remove ContentKey");
            Console.WriteLine("    --removeauthpolicy: <PId>        Remove ContentKeyAuthorizationPolicy and assoiated Options");
            Console.WriteLine("    --removeauthpolicyoption: <Pid>  Remove ContentKeyAuthorizationPolicyOption");
        }

        static private List<string> GetOptions(string[] args, ref Ops op)
        {
            List<string> idArray = new List<string>();
            op = Ops.None;
            if (args.Length == 0)
            {
                return idArray;
            }
            switch (args[0])
            {
                case "--listall":
                    op = Ops.ListAll;
                    break;
                case "--listcontentkey":
                    op = Ops.ListContentKey;
                    break;
                case "--listauthpolicy":
                    op = Ops.ListAuthPolicy;
                    break;
                case "--listauthpolicyoption":
                    op = Ops.ListAuthPolicyOption;
                    break;
                case "--removecontentkey":
                    if (args.Length > 1)
                    {
                        op = Ops.RemoveContentKey;
                        for (int i = 1; i < args.Length; i++)
                        {
                            idArray.Add(args[i]);
                        }
                    }
                    break;
                case "--removeauthpolicy":
                    if (args.Length > 1)
                    {
                        op = Ops.RemoveAuthPolicy;
                        for (int i = 1; i < args.Length; i++)
                        {
                            idArray.Add(args[i]);
                        }
                    }
                    break;
                case "--removeauthpolicyoption":
                    if (args.Length > 1)
                    {
                        op = Ops.RemoveAuthPolicyOption;
                        for (int i = 1; i < args.Length; i++)
                        {
                            idArray.Add(args[i]);
                        }
                    }
                    break;
                case "--createdrmauthpolicy":
                    op = Ops.CreateDrmAuthPolicy;
                    break;
                case "--deletedrmauthpolicy":
                    op = Ops.DeleteDrmAuthPolicy;
                    break;
                case "--applydrmauthpolicytoasset":
                    if (args.Length > 1)
                    {
                        op = Ops.RegisterDrmAuthPolicyToAsset;
                        for (int i = 1; i < args.Length; i++)
                        {
                            idArray.Add(args[i]);
                        }
                    }
                    break;
                case "--deletedrmauthpolicyfromasset":
                    if (args.Length > 1)
                    {
                        op = Ops.UnregisterDrmAuthPolicyToAsset;
                        for (int i = 1; i < args.Length; i++)
                        {
                            idArray.Add(args[i]);
                        }
                    }
                    break;
                default:
                    op = Ops.None;
                    break;
            }

            Console.WriteLine("Ops = {0}", op);
            if (op != Ops.None)
                foreach (var id in idArray)
                    Console.WriteLine("Target Id = {0}", id);
            return idArray;
        }
    }
}