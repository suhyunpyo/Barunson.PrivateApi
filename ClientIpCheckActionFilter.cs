using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Options;
using System.Net;

namespace Barunson.PrivateApi
{
	public class ClientIpCheckActionFilter : IActionFilter
	{
        private readonly List<IPAddress> _allowIps;
        public ClientIpCheckActionFilter(List<IPAddress> allowips)
		{
            _allowIps = allowips;

        }
        public void OnActionExecuting(ActionExecutingContext context)
		{
			var isAllow = false;

            var allowList = new List<IPAddress>
            {
                //기본 허용 IP 추가
                IPAddress.Loopback,
                IPAddress.IPv6Loopback
            };
            allowList.AddRange(_allowIps);

			var remoteIp = context.HttpContext.Connection.RemoteIpAddress;
			if (remoteIp != null)
			{
				if (remoteIp.IsIPv4MappedToIPv6)
				{
					remoteIp = remoteIp.MapToIPv4();
				}
				if (remoteIp.ToString().StartsWith("172.16."))
					isAllow = true;
				else
				{
					isAllow = allowList.Any(m => m.Equals(remoteIp));
				}
			}
			if (!isAllow)
			{
				context.Result = new BadRequestObjectResult("접속권한 없음.");
			}
		}

		public void OnActionExecuted(ActionExecutedContext context)
		{
			// Do something after the action executes.
		}

		
	}
}
