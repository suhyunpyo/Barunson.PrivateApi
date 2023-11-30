using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Barunson.PrivateApi.Model;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Barunson.PrivateApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class NiceController : ControllerBase
    {
        private readonly ILogger<NiceController> _logger;
        private readonly SecretClient secretClient;
        private readonly IHttpClientFactory _httpClientFactory;

        private NiceTokenInfo _cryptoTokens { get; set; }
        private NiceApiClientInfo? _clientInfo { get; set; }
        //한국어 인코딩을 사용해야 함. utf-8 사용시 암호화 교환 못함.
        private readonly Encoding _defaultEncoding;

        public NiceController(ILogger<NiceController> logger, IHttpClientFactory httpClientFactory, NiceTokenInfo niceTokenInfo)
        {
            _logger = logger;
            secretClient = new SecretClient(vaultUri: new Uri("https://barunsecret.vault.azure.net/"), credential: new DefaultAzureCredential());
            _httpClientFactory = httpClientFactory;
            _cryptoTokens = niceTokenInfo;

            _defaultEncoding = CodePagesEncodingProvider.Instance.GetEncoding(51949);
        }

        /// <summary>
        /// 기관 토큰(통합형)
        /// </summary>
        /// <returns></returns>
        private async Task<NiceApiClientInfo> GetNiceApiClientInfo()
        {
            if (_clientInfo == null)
            {
                var info = new NiceApiClientInfo();

                info.AccessToken = (await secretClient.GetSecretAsync("NiceApiClient--AccessToken")).Value.Value;
                info.ClientId = (await secretClient.GetSecretAsync("NiceApiClient--ClientID")).Value.Value;
                info.ClientSecret = (await secretClient.GetSecretAsync("NiceApiClient--ClientSecret")).Value.Value;
                info.ProductId = "2101979031";

                _clientInfo = info;
            }
            return _clientInfo;
        }

        private static long GetUnixTimeStemp()
        {
            var time = (DateTime.Now.ToUniversalTime() - new DateTime(1970, 1, 1));
            return (long)(time.TotalSeconds);
        }

        /// <summary>
        /// 암호화 토큰 요청
        /// </summary>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        private async Task<NiceApiCryptoTokenInfo> GetCryptoToken(string productId)
        {
            var now = DateTime.Now;

            var _cryptoToken = _cryptoTokens.Tokens.Values
                .OrderByDescending(m => m.ExpiresDateTime)
                .FirstOrDefault(m => m.ExpiresDateTime > now && m.ProdcutId == productId);
            if (_cryptoToken == null)
            {
                await GetNiceApiClientInfo();

                var timestemp = GetUnixTimeStemp();
                _cryptoToken = new NiceApiCryptoTokenInfo
                {
                    Reqdtim = now.ToString("yyyyMMddHHmmss"),
                    Reqno = "REQ" + now.Ticks.ToString(),
                    Token = null,
                    ExpiresDateTime = now,
                    Period = 0,
                    ProdcutId = productId,
                };

                var apiUri = new Uri(_clientInfo.ServiceUrl, "/digital/niceid/api/v1.0/common/crypto/token");
                var httpClient = _httpClientFactory.CreateClient("niceapiHandler");

                var encData_byte = Encoding.ASCII.GetBytes($"{_clientInfo.AccessToken}:{timestemp}:{_clientInfo.ClientId}");

                var postData = new NiceApiCryptoRequest
                {
                    dataHeader = new NiceApiCryptoRequestDataHeader { CNTY_CD = "ko" },
                    dataBody = new NiceApiCryptoRequestDataBody
                    {
                        req_dtim = _cryptoToken.Reqdtim,
                        req_no = _cryptoToken.Reqno,
                        enc_mode = "1"
                    }
                };
                using (var request = new HttpRequestMessage())
                {
                    request.Method = HttpMethod.Post;
                    request.RequestUri = apiUri;
                    request.Headers.Authorization = new AuthenticationHeaderValue("bearer", Convert.ToBase64String(encData_byte));
                    request.Headers.Add("client_id", _clientInfo.ClientId);
                    request.Headers.Add("productID", productId);

                    request.Content = JsonContent.Create(postData);

                    var response = await httpClient.SendAsync(request);
                    response.EnsureSuccessStatusCode();

                    //api 응답 서버에서 charset=utf-8 표준 규칙을 지키지 않아 인코딩을 직접 해야 함..   charset=UTF8로 응답.                    
                    var resBytes = await response.Content.ReadAsByteArrayAsync();
                    var resString = Encoding.UTF8.GetString(resBytes);
                    var resItem = JsonSerializer.Deserialize<NiceApiCryptoResponse>(resString);

                    if (resItem != null && resItem.dataHeader.GW_RSLT_CD == "1200")
                    {
                        _cryptoToken.Token = resItem.dataBody.token_val;
                        _cryptoToken.Period = resItem.dataBody.period;
                        _cryptoToken.ExpiresDateTime = DateTime.Now.AddSeconds(resItem.dataBody.period - 5);
                        _cryptoToken.SiteCode = resItem.dataBody.site_code;
                        _cryptoToken.TokenVersionId = resItem.dataBody.token_version_id;

                        var shaval = _cryptoToken.Reqdtim.Trim() + _cryptoToken.Reqno.Trim() + _cryptoToken.Token.Trim();
                        using (var mySHA256 = SHA256.Create())
                        {
                            var arrHashValue = mySHA256.ComputeHash(_defaultEncoding.GetBytes(shaval));
                            var base64Value = Convert.ToBase64String(arrHashValue);

                            _cryptoToken.Key = _defaultEncoding.GetBytes(base64Value[..16]);
                            _cryptoToken.IV = _defaultEncoding.GetBytes(base64Value[^16..]);
                            _cryptoToken.HMAC = _defaultEncoding.GetBytes(base64Value[..32]);
                        }

                        _cryptoTokens.Tokens.TryAdd(_cryptoToken.TokenVersionId, _cryptoToken);
                    }
                    else
                        throw new Exception();
                }
            }
            return _cryptoToken;
        }

        /// <summary>
        /// 나이스 인증용 암호화
        /// </summary>
        /// <param name="productId"></param>
        /// <param name="returnUrl"></param>
        /// <param name="receiveData"></param>
        /// <param name="methodType"></param>
        /// <param name="popupYn"></param>
        /// <returns></returns>

        private async Task<ActionResult<NiceCryptoResponse>> GetProductEncData(string productId, string returnUrl, string? receiveData, string? methodType, string? popupYn, string? authType)
        {
            var token = await GetCryptoToken(productId);  
            var integrityValue = string.Empty;
            string encData = string.Empty;

            var reqData = new NiceApiRequestData
            {
                RequestNo = $"REQ{DateTime.Now:yyMMddHHmmssff}",
                ReturnUrl = returnUrl,
                SiteCode = token.SiteCode,
                MethodType = methodType ?? "post",
                PopupYn = popupYn,
                ReceiveData = receiveData ?? "",
                AuthType = authType
            };
            var reqStr = JsonSerializer.Serialize(reqData);

            using (var aesEnc = Aes.Create())
            {
                aesEnc.Key = token.Key;
                aesEnc.IV = token.IV;
                aesEnc.Mode = CipherMode.CBC;
                aesEnc.Padding = PaddingMode.PKCS7;

                var encryptor = aesEnc.CreateEncryptor(aesEnc.Key, aesEnc.IV);
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt, _defaultEncoding))
                        {
                            await swEncrypt.WriteAsync(reqStr);
                        }
                    }
                    var encBytes = msEncrypt.ToArray();
                    encData = Convert.ToBase64String(encBytes);
                }
            }
            using (var hmac = new HMACSHA256(token.HMAC))
            {
                var hashValue = hmac.ComputeHash(_defaultEncoding.GetBytes(encData));
                integrityValue = Convert.ToBase64String(hashValue);
            }
            return new NiceCryptoResponse
            {
                TokenVersionId = token.TokenVersionId,
                EncData = encData,
                IntegrityValue = integrityValue,
            };
        }
        /// <summary>
        /// 통합 인증용 암호화
        /// </summary>
        /// <param name="returnUrl">콜백 받을 경로</param>
        /// <param name="receiveData">인증 후 전달받을 데이터 세팅 (요청값 그대로 리턴)</param>
        /// <param name="methodType"></param>
        /// <param name="popupYn"></param>
        /// <returns></returns>
        [HttpGet("Encrypt")]
        public async Task<ActionResult<NiceCryptoResponse>> GetEncData(string returnUrl, string? receiveData, string? methodType, string? popupYn, string? authType = null)
        {
            //통합인증 상품 ID
            return await GetProductEncData("2101979031", returnUrl, receiveData, methodType, popupYn ?? "Y", authType);
        }

        /// <summary>
        /// 아이핀 인증용 암호화
        /// </summary>
        /// <param name="returnUrl"></param>
        /// <param name="receiveData"></param>
        /// <param name="methodType"></param>
        /// <param name="popupYn"></param>
        /// <returns></returns>
        [HttpGet("IpinEncrypt")]
        public async Task<ActionResult<NiceCryptoResponse>> GetIpinEncData(string returnUrl, string? receiveData, string? methodType)
        {
            //아이핀 상품 ID
            return await GetProductEncData("2101434007", returnUrl, receiveData, methodType, null, null);
        }

        /// <summary>
        /// 나이스 인증 결과 복호화
        /// </summary>
        /// <param name="tokenVersionId">토큰버전아이디</param>
        /// <param name="encData"></param>
        /// <param name="integrityValue"></param>
        /// <returns></returns>
        [HttpGet("Decrypt")]
        public async Task<ActionResult<NiceApiResponseData>> GetDesData(string tokenVersionId, string encData, string integrityValue)
        {
            var token = _cryptoTokens.Tokens.GetValueOrDefault(tokenVersionId);
            if (token == null)
            {
                return BadRequest();
            }
            NiceApiResponseData? result = null;
            var cipherEnc = Convert.FromBase64String(encData);

            using (var aesEnc = Aes.Create())
            {
                aesEnc.Key = token.Key;
                aesEnc.IV = token.IV;
                aesEnc.Mode = CipherMode.CBC;
                aesEnc.Padding = PaddingMode.PKCS7;

                var decryptor = aesEnc.CreateDecryptor(aesEnc.Key, aesEnc.IV);

                using (MemoryStream msDecrypt = new MemoryStream(cipherEnc))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt, _defaultEncoding))
                        {
                            var plaintext = await srDecrypt.ReadToEndAsync();
                            result = JsonSerializer.Deserialize<NiceApiResponseData>(plaintext);
                        }
                    }
                }
            }

            if (result == null)
                return BadRequest();
            else
                return result;
        }

        /// <summary>
        /// 나이스 인증(아이핀) 결과 복호화
        /// </summary>
        /// <param name="tokenVersionId">토큰버전아이디</param>
        /// <param name="encData"></param>
        /// <param name="integrityValue"></param>
        /// <returns></returns>
        [HttpGet("IpinDecrypt")]
        public async Task<ActionResult<NiceIPinApiResponseData>> GetIPinDesData(string tokenVersionId, string encData, string integrityValue)
        {
            var token = _cryptoTokens.Tokens.GetValueOrDefault(tokenVersionId);
            if (token == null)
            {
                return BadRequest();
            }
            NiceIPinApiResponseData? result = null;
            var cipherEnc = Convert.FromBase64String(encData);

            using (var aesEnc = Aes.Create())
            {
                aesEnc.Key = token.Key;
                aesEnc.IV = token.IV;
                aesEnc.Mode = CipherMode.CBC;
                aesEnc.Padding = PaddingMode.PKCS7;

                var decryptor = aesEnc.CreateDecryptor(aesEnc.Key, aesEnc.IV);

                using (MemoryStream msDecrypt = new MemoryStream(cipherEnc))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt, _defaultEncoding))
                        {
                            var plaintext = await srDecrypt.ReadToEndAsync();
                            result = JsonSerializer.Deserialize<NiceIPinApiResponseData>(plaintext);
                        }
                    }
                }
            }

            if (result == null)
                return BadRequest();
            else
                return result;
        }
    }       
}
