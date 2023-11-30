using Barunson.PrivateApi.Model;
using System.Net;

namespace Barunson.PrivateApi
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            builder.Services.AddEndpointsApiExplorer();

            builder.Services.AddSwaggerGen();
            builder.Services.AddHttpClient();

            //Ncie ���� API�� ���� ���� ���� ����. 
            builder.Services.AddHttpClient("niceapiHandler")
                .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
                {
                    SslProtocols = System.Security.Authentication.SslProtocols.Tls12,
                });
            builder.Services.AddSingleton<NiceTokenInfo>();

            //���� ���Ͽ��� ��� IP ����� ����
            var alowIpliststring = builder.Configuration.GetSection("AllowIPList").Get<List<string>>();

            builder.Services.AddSingleton<List<IPAddress>>(alowIpliststring.Select(m => IPAddress.Parse(m)).ToList());
            builder.Services.AddControllers(config =>
            {
                config.Filters.Add<ClientIpCheckActionFilter>();
            });

            var app = builder.Build();

            app.UseSwagger();
            app.UseSwaggerUI();

            app.UseHttpsRedirection();

            app.UseAuthorization();

            app.MapControllers();

            app.Run();
        }
    }
}