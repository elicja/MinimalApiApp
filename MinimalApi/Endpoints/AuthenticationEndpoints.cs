using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using MinimalApi.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace MinimalApi.Endpoints;

public static class AuthenticationEndpoints
{
    public static void AddAuthenticationEndpoints(this WebApplication app)
    {
         app.MapPost("/api/token", (IConfiguration config, [FromBody] AuthenticationData data) =>
        {
            var user = ValidateCredentials(data);

            if (user is null)
            {
                return Results.Unauthorized();
            }

            string token = GenerateToken(user, config);

            return Results.Ok(token);
        });
    }

    private static string GenerateToken(UserData user, IConfiguration config)
    {
        var secretKey = new SymmetricSecurityKey(
            Encoding.ASCII.GetBytes(
                config.GetValue<string>("Authentication:SecretKey")));

        var signingCredentials = new SigningCredentials(secretKey, SecurityAlgorithms.HmacSha256);

        List<Claim> claims = new();
        claims.Add(new(JwtRegisteredClaimNames.Sub, user.Id.ToString()));
        claims.Add(new(JwtRegisteredClaimNames.UniqueName, user.UserName));
        claims.Add(new(JwtRegisteredClaimNames.GivenName, user.FirstName));
        claims.Add(new(JwtRegisteredClaimNames.FamilyName, user.LastName));

        var token = new JwtSecurityToken(
            config.GetValue<string>("Authentication:Issuer"),
            config.GetValue<string>("Authentication:Audience"),
            claims,
            DateTime.UtcNow,
            DateTime.UtcNow.AddMinutes(1),
            signingCredentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private static UserData? ValidateCredentials(AuthenticationData data)
    {
        // This is not a production code, replace it with a call to your auth system
        if (CompareValues(data.UserName, "alicjak") &&
            CompareValues(data.Password, "Test1234"))
        {
            return new UserData(1, "Alicja", "Kowalska", data.UserName!);
        }

        if (CompareValues(data.UserName, "andrzejn") &&
            CompareValues(data.Password, "Test1234"))
        {
            return new UserData(2, "Andrzej", "Nowak", data.UserName!);
        }

        return null;
    }

    private static bool CompareValues(string? actual, string expected)
    {
        if (actual is not null)
        {
            if (actual.Equals(expected))
            {
                return true;
            }
        }

        return false;
    }
}
