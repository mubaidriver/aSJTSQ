unit KeyVerification;

interface

uses IdHTTP, System.SysUtils, System.Classes, System.JSON, System.DateUtils, IdHashMessageDigest, Vcl.Forms,
  Winapi.Windows;

type

  //�����֤
  TAuthentication = class
  private
    m_appkey: string;  //�����Կ
    m_token: string;  //��¼���ص�token����
    m_cdkey: string;  //��¼��Կ
  public
    constructor Create;
    destructor Destroy; override;
    function SoftwareInit: Boolean;
    function cdkeyLogin: Boolean;
    function LoadCdkey: string;
    function cdkeyLoginHeartbeat: Boolean;
  end;

var
  g_Authentication: TAuthentication;

const
  _STR_CDK_FILE = 'License.key';

implementation

uses Log, VMProtectSDK, Grobal, Main, GlobalVar;

{ TAuthentication }

function TAuthentication.cdkeyLogin: Boolean;
begin
  Result := True;
end;

function TAuthentication.cdkeyLoginHeartbeat: Boolean;
begin

end;

constructor TAuthentication.Create;
begin

end;

destructor TAuthentication.Destroy;
begin

  inherited;
end;

function TAuthentication.LoadCdkey: string;
begin

end;

function TAuthentication.SoftwareInit: Boolean;
begin

end;

end.
