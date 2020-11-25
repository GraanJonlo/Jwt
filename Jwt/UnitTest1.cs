using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Jwt
{
	public class UnitTest1
	{
		[Fact]
		public void Test1()
		{
			// Something in .NET has a minimum limit of 2048 bits for signing keys
			var rsa = new RSACryptoServiceProvider(2048);
			var privateRsaParams = rsa.ExportParameters(true);
			var publicRsaParams = rsa.ExportParameters(false);

			var privateKey = new RsaSecurityKey(privateRsaParams);
			var publicKey = new RsaSecurityKey(publicRsaParams);

			int accountId = 1234;
			var roles = new[] {"Foo", "Bar", "Baz"};

			var token = GenerateJwtToken(accountId, roles, privateKey);

			Tuple<int?, string[]> accountAndRoles = ValidateJwtToken(token, publicKey);

			Assert.Equal(new Tuple<int?, string[]>(accountId, roles), accountAndRoles);
		}

		public string GenerateJwtToken(int accountId, string[] roles, RsaSecurityKey privateKey)
		{
			var serializedRoles = string.Join(',', roles);
			var tokenHandler = new JwtSecurityTokenHandler();
			byte[] key = Encoding.ASCII.GetBytes("Super secret key");
			var tokenDescriptor =
				new SecurityTokenDescriptor
				{
					Subject =
						new ClaimsIdentity(new[]
						{
							new Claim("id", accountId.ToString()), new Claim("roles", serializedRoles)
						}),
					Expires = DateTime.UtcNow.AddMinutes(5),
					/*SigningCredentials =
						new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),*/
					SigningCredentials = new SigningCredentials(privateKey,
						SecurityAlgorithms.RsaSha512Signature, SecurityAlgorithms.Sha512Digest),
					Issuer = "URL for the site that issued the token (OPTIONAL)",
					Audience = "URL for the site receiving the token (OPTIONAL)"
				};

			var securityToken = tokenHandler.CreateToken(tokenDescriptor);
			return tokenHandler.WriteToken(securityToken);
		}

		public Tuple<int?, string[]> ValidateJwtToken(string token, RsaSecurityKey publicKey)
		{
			var tokenHandler = new JwtSecurityTokenHandler();
			var key = Encoding.ASCII.GetBytes("Super secret key");
			try
			{
				tokenHandler.ValidateToken(token, new TokenValidationParameters
				{
					ValidateIssuerSigningKey = true,
					/*IssuerSigningKey = new SymmetricSecurityKey(key),*/
					IssuerSigningKey = publicKey,
					ValidateAudience = true,
					ValidAudience =
						"URL for the site receiving the token (OPTIONAL)", // Can supply 1 or many valid audiences
					ValidAudiences = new[] {"URL for the site receiving the token (OPTIONAL)"},
					ValidateIssuer = true,
					ValidIssuer =
						"URL for the site that issued the token (OPTIONAL)", // Can supply 1 or many valid issuers
					ValidIssuers = new[] {"URL for the site that issued the token (OPTIONAL)"},
					// set clockskew to zero so tokens expire exactly at token expiration time (instead of 5 minutes later)
					ClockSkew = TimeSpan.Zero,
				}, out SecurityToken validatedToken);

				var jwtToken = (JwtSecurityToken)validatedToken;
				var accountId = int.Parse(jwtToken.Claims.First(x => x.Type == "id").Value);
				var roles = jwtToken.Claims.First(x => x.Type == "roles").Value.Split(',');

				return new Tuple<int?, string[]>(accountId, roles);
			}
			catch (Exception e)
			{
				// If the token fails validation it throws an exception
				return null;
			}
		}
	}
}
