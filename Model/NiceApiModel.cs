using System.Collections.Concurrent;
using System.Text.Json.Serialization;

namespace Barunson.PrivateApi.Model
{
    /// <summary>
    /// 인증 토큰 모록 저장.
    /// App 전역에서 동시 접속하기하여 sigletone으로 선언됨.
    /// </summary>
    public class NiceTokenInfo
    {
        public ConcurrentDictionary<string, NiceApiCryptoTokenInfo> Tokens { get; set; } = new ConcurrentDictionary<string, NiceApiCryptoTokenInfo>();
    }
    /// <summary>
    /// 나이스 인증 클라이언트 정보
    /// </summary>
    public class NiceApiClientInfo
    {
        public string ClientId { get; set; } = "";
        public string ClientSecret { get; set; } = "";
        public string AccessToken { get; set; } = "";
        public Uri ServiceUrl { get; set; } = new Uri("https://svc.niceapi.co.kr:22001/"); 
        public string ProductId { get; set; } = "2101979031";
    }

    /// <summary>
    /// Nice 인증을 위한 요청 암호화 데이터
    /// </summary>
    public class NiceCryptoResponse
    {
        /// <summary>
        /// 사용한 토큰의 버전 아이디. 복호화시 필요한 키값
        /// </summary>
        public string TokenVersionId { get; set; }
        /// <summary>
        /// 암호화된 데이터
        /// </summary>
        public string EncData { get; set; }
        /// <summary>
        /// 암호화 무결성 값
        /// </summary>
        public string IntegrityValue { get; set; }
    }

    /// <summary>
    /// 암호화키 요청 모델
    /// </summary>
    public class NiceApiCryptoRequest
    {
        public NiceApiCryptoRequestDataHeader dataHeader { get; set; } = new NiceApiCryptoRequestDataHeader();
        public NiceApiCryptoRequestDataBody dataBody { get; set; } = new NiceApiCryptoRequestDataBody();

    }
    /// <summary>
    /// 암호화키 요청 본문 헤더
    /// </summary>
    public class NiceApiCryptoRequestDataHeader
    {
        /// <summary>
        /// 이용언어 : ko, en, cn … 
        /// </summary>
        public string CNTY_CD { get; set; } = "ko";
    }
    /// <summary>
    /// 암호화키 요청 본문
    /// </summary>
    /// <example>
    /// {"req_dtim": "20210622162600",
    ///  "req_no":"111111111122222222223333333333",
    ///  "enc_mode":"1"}
    /// </example>
    public class NiceApiCryptoRequestDataBody
    {
        /// <summary>
        /// 요청일시 (YYYYMMDDHH24MISS): 14자
        /// </summary>
        public string req_dtim { get; set; }
        /// <summary>
        /// 요청고유번호: 30자
        /// </summary>
        public string req_no { get; set; }
        /// <summary>
        /// 사용할 암복호화 구분
        /// 1 : AES128/CBC/PKCS7
        /// </summary>
        public string enc_mode { get; set; } = "1";
    }

    /// <summary>
    /// 암호화키 응답 모델
    /// </summary>
    public class NiceApiCryptoResponse
    {
        public NiceApiCryptoResponseDataHeader dataHeader { get; set; }
        public NiceApiCryptoResponseDataBody dataBody { get; set; }

    }
    /// <summary>
    /// 암호화키 응답 헤더
    /// </summary>
    public class NiceApiCryptoResponseDataHeader
    {
        /// <summary>
        /// 응답코드(정상:1200, 오류코드는 규격탭 참조)
        /// </summary>
        public string GW_RSLT_CD { get; set; }
        /// <summary>
        /// 응답메시지 (한글 또는 영문)
        /// </summary>
        public string GW_RSLT_MSG { get; set; }
    }
    /// <summary>
    /// 암호화키 응답 본문
    /// </summary>
    public class NiceApiCryptoResponseDataBody
    {
        /// <summary>
        /// dataBody 정상처리여부 (P000 성공, 이외 모두 오류)
        /// </summary>
        public string rsp_cd { get; set; }
        /// <summary>
        /// rsp_cd가 "EAPI"로 시작될 경우 오류 메시지 세팅
        /// </summary>
        public string res_msg { get; set; }
        /// <summary>
        /// rsp_cd가 P000일 때 상세결과코드
        ///    - 0000: 발급 성공
        ///    - 0001: 필수입력값 오류
        ///    - 0003: OTP 발급 대상 회원사 아님
        ///    - 0099: 기타오류
        /// </summary>
        public string result_cd { get; set; }
        /// <summary>
        /// 사이트코드
        /// </summary>
        public string site_code { get; set; }
        /// <summary>
        /// 서버 토큰 버전
        /// </summary>
        public string token_version_id { get; set; }
        /// <summary>
        /// 암복호화를 위한 서버 토큰 값
        /// </summary>
        public string token_val { get; set; }
        /// <summary>
        /// 토큰의 만료까지 남은 period(초)
        /// </summary>
        public double period { get; set; }
    }

    /// <summary>
    /// 암호화 토큰 정보
    /// </summary>
    public class NiceApiCryptoTokenInfo
    {
        // <summary>
        /// 요청일시 (YYYYMMDDHH24MISS): 14자
        /// </summary>
        public string? Reqdtim { get; set; }
        /// <summary>
        /// 요청고유번호: 30자
        /// </summary>
        public string? Reqno { get; set; }
        public string? Token { get; set; }
        public double Period { get; set; }
        public DateTime ExpiresDateTime { get; set; } = DateTime.Now;

        public string? SiteCode { get; set; }
        public string? TokenVersionId { get; set; }

        public byte[]? Key { get; set; }
        public byte[]? IV { get; set; }
        public byte[]? HMAC { get; set; }

        /// <summary>
        /// 상품 고유 번호
        /// </summary>
        public string ProdcutId { get; set; }
    }

    /// <summary>
    /// 요청 데이터
    /// </summary>
    public class NiceApiRequestData
    {
        /// <summary>
        /// [필수] 서비스 요청 고유 번호
        /// </summary>
        [JsonPropertyName("requestno")]
        public string? RequestNo { get; set; }

        /// <summary>
        /// [필수] 인증결과를 받을 회원사 url
        /// </summary>
        [JsonPropertyName("returnurl")]
        public string? ReturnUrl { get; set; }

        /// <summary>
        /// [필수] 암호화토큰요청 API에 응답받은 site_code
        /// </summary>
        [JsonPropertyName("sitecode")]
        public string? SiteCode { get; set; }

        /// <summary>
        /// 인증수단 고정
        /// (M:휴대폰인증,C:카드본인확인인증,X:인증서인증,U:공동인증서인증,F:금융인증서인증,S:PASS인증서인증)
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        [JsonPropertyName("authtype")]
        public string? AuthType { get; set; }
        /// <summary>
        /// 결과 url 전달시 http method타입
        /// post,get
        /// </summary>
        [JsonPropertyName("methodtype")]
        public string MethodType { get; set; } = "post";

        /// <summary>
        /// Y, N
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        [JsonPropertyName("popupyn")]
        public string? PopupYn { get; set; }

        /// <summary>
        /// 인증 후 전달받을 데이터 세팅 (요청값 그대로 리턴)
        /// </summary>
        [JsonPropertyName("receivedata")]
        public string ReceiveData { get; set; } = "";
    }

    /// <summary>
    /// 응답 데이터
    /// </summary>
    public class NiceApiResponseData
    {
        /// <summary>
        /// 결과코드 result_code가 성공(0000)일 때만 전달
        /// </summary>
        [JsonPropertyName("resultcode")]
        public string? ResultCode { get; set; }

        /// <summary>
        /// [필수] 서비스 요청 고유 번호
        /// </summary>
        [JsonPropertyName("requestno")]
        public string? RequestNo { get; set; }

        /// <summary>
        /// 암호화 일시(YYYYMMDDHH24MISS)
        /// </summary>
        [JsonPropertyName("enctime")]
        public string? EncTime { get; set; }

        /// <summary>
        /// [필수] 암호화토큰요청 API에 응답받은 site_code
        /// </summary>
        [JsonPropertyName("sitecode")]
        public string? SiteCode { get; set; }

        /// <summary>
        /// 응답고유번호
        /// </summary>
        [JsonPropertyName("responseno")]
        public string? ResponseNo { get; set; }

        /// <summary>
        /// 인증수단
        /// M	휴대폰인증		
        /// C 카드본인확인
        /// X 공동인증서
        /// F 금융인증서
        /// S PASS인증서
        /// </summary>
        [JsonPropertyName("authtype")]
        public string? AuthType { get; set; }

        /// <summary>
        /// 이름
        /// </summary>
        [JsonPropertyName("name")]
        public string? Name { get; set; }

        /// <summary>
        /// UTF8로 URLEncoding된 이름 값
        /// </summary>
        [JsonPropertyName("utf8_name")]
        public string? utf8_name { get; set; }

        /// <summary>
        /// 생년월일 8자리
        /// </summary>
        [JsonPropertyName("birthdate")]
        public string? BirthDate { get; set; }

        /// <summary>
        /// 성별 0:여성, 1:남성
        /// </summary>
        [JsonPropertyName("gender")]
        public string? Gender { get; set; }

        /// <summary>
        /// 내외국인 0:내국인, 1:외국인
        /// </summary>
        [JsonPropertyName("nationalinfo")]
        public string? NationalInfo { get; set; }

        /// <summary>
        /// 이통사 구분(휴대폰 인증 시)
        /// 1	SK텔레콤		
        /// 2	KT		
        /// 3	LGU+		
        /// 5	SK텔레콤 알뜰폰		
        /// 6	KT 알뜰폰		
        /// 7	LGU+ 알뜰폰
        /// </summary>
        [JsonPropertyName("mobileco")]
        public string? MobileCo { get; set; }

        /// <summary>
        /// 휴대폰 번호(휴대폰 인증 시)
        /// </summary>
        [JsonPropertyName("mobileno")]
        public string? MobileNo { get; set; }

        /// <summary>
        /// 개인 식별 코드(CI)
        /// </summary>
        [JsonPropertyName("ci")]
        public string? ci { get; set; }

        /// <summary>
        /// 개인 식별 코드(di)
        /// </summary>
        [JsonPropertyName("di")]
        public string? di { get; set; }

        /// <summary>
        /// 사업자번호(법인인증서 인증시)
        /// </summary>
        [JsonPropertyName("businessno")]
        public string? BusinessNo { get; set; }

        /// <summary>
        /// 인증 후 전달받을 데이터 세팅 (요청값 그대로 리턴)
        /// </summary>
        [JsonPropertyName("receivedata")]
        public string ReceiveData { get; set; } = "";
    }

    public class NiceIPinApiResponseData
    {
        /// <summary>
        /// 결과코드 result_code가 성공(1)일 때만 전달
        /// </summary>
        [JsonPropertyName("resultcode")]
        public string? ResultCode { get; set; }

        /// <summary>
        /// [필수] 서비스 요청 고유 번호
        /// </summary>
        [JsonPropertyName("requestno")]
        public string? RequestNo { get; set; }

        /// <summary>
        /// 암호화 일시(YYYYMMDDHH24MISS)
        /// </summary>
        [JsonPropertyName("enctime")]
        public string? EncTime { get; set; }

        /// <summary>
        /// [필수] 암호화토큰요청 API에 응답받은 site_code
        /// </summary>
        [JsonPropertyName("sitecode")]
        public string? SiteCode { get; set; }

        /// <summary>
        /// 인증서버 아이피
        /// </summary>
        [JsonPropertyName("ipaddr")]
        public string? Ipaddr { get; set; }

        
        /// <summary>
        /// 이름
        /// </summary>
        [JsonPropertyName("name")]
        public string? Name { get; set; }

        /// <summary>
        /// UTF8로 URLEncoding된 이름 값
        /// </summary>
        [JsonPropertyName("utf8_name")]
        public string? utf8_name { get; set; }

        /// <summary>
        /// 아이핀 번호
        /// </summary>
        [JsonPropertyName("vnumber")]
        public string? VNumber { get; set; }
        
        /// <summary>
        /// 성별 0:여성, 1:남성
        /// </summary>
        [JsonPropertyName("gendercode")]
        public string? Gender { get; set; }

        /// <summary>
        /// 생년월일 8자리
        /// </summary>
        [JsonPropertyName("birthdate")]
        public string? BirthDate { get; set; }

        /// <summary>
        /// 내외국인 0:내국인, 1:외국인
        /// </summary>
        [JsonPropertyName("nationalinfo")]
        public string? NationalInfo { get; set; }

        /// <summary>
        /// 연령 코드
        /// </summary>
        [JsonPropertyName("agecode")]
        public string? AgeCode { get; set; }

        /// <summary>
        /// 개인 식별 코드 (CI)
        /// </summary>
        [JsonPropertyName("coinfo1")]
        public string? ConInfo1 { get; set; }

        /// <summary>
        /// 개인 식별 코드 (CI2)
        /// </summary>
        [JsonPropertyName("coinfo2")]
        public string? ConInfo2 { get; set; }

        /// <summary>
        /// 개인 식별 코드(di)
        /// </summary>
        [JsonPropertyName("dupinfo")]
        public string? DupInfo { get; set; }

        /// <summary>
        /// CI 버전 정보
        /// </summary>
        [JsonPropertyName("ciupdate")]
        public string? CiUpdate { get; set; }

        /// <summary>
        /// 인증 후 전달받을 데이터 세팅 (요청값 그대로 리턴)
        /// </summary>
        [JsonPropertyName("receivedata")]
        public string ReceiveData { get; set; } = "";
    }
}
