using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Barunson.PrivateApi.Model;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Barunson.PrivateApi.Controllers
{
	[ApiController]
	[Route("api/[controller]")]
	public class MertController : ControllerBase
	{
		private readonly ILogger<MertController> _logger;
		private readonly SecretClient secretClient;
		public MertController(ILogger<MertController> logger)
		{
			_logger = logger;
			secretClient = new SecretClient(vaultUri: new Uri("https://barunsecret.vault.azure.net/"), credential: new DefaultAzureCredential());
		}

		[HttpGet("Prod/{id}")]
		public async Task<ActionResult<PgMertInfo>> GetProd(string id)
		{
			PgMertInfo? result = null;
			var secret = await secretClient.GetSecretAsync("PgMertInfos");
			if (secret != null)
			{
				var secretval = secret.Value?.Value;
				if (!string.IsNullOrWhiteSpace(secretval))
				{
					var pgInfos = JsonSerializer.Deserialize<List<PgMertInfo>>(secretval);

					result = pgInfos?.FirstOrDefault(pgInfos => pgInfos.Id == id);
				}
			}
			if (result == null)
			{
				return NotFound();
			}
			return result;
		}
		[HttpGet("Dev/{id}")]
		public async Task<ActionResult<PgMertInfo>> GetDev(string id)
		{
			PgMertInfo? result = null;
			var secret = await secretClient.GetSecretAsync("DevPgMertInfos");
			if (secret != null)
			{
				var secretval = secret.Value?.Value;
				if (!string.IsNullOrWhiteSpace(secretval))
				{
					var pgInfos = JsonSerializer.Deserialize<List<PgMertInfo>>(secretval);

					result = pgInfos?.FirstOrDefault(pgInfos => pgInfos.Id == id);
				}
			}
			if (result == null)
			{
				return NotFound();
			}
			return result;
		}

	}
}
