using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using System.Net;
using WebAuthorisationPolicy.Models;

namespace WebAuthorisationPolicy.PermissionHandlers;

// https://github.com/dotnet/aspnetcore/blob/main/src/Security/samples/CustomAuthorizationFailureResponse/Authorization/SampleAuthorizationMiddlewareResultHandler.cs#L28
public class RedirectAuthorizationMiddlewareResultHandler : IAuthorizationMiddlewareResultHandler
{
    private readonly AuthorizationMiddlewareResultHandler _handler = new();
    public async Task HandleAsync(
        RequestDelegate next,
        HttpContext context,
        AuthorizationPolicy policy,
        PolicyAuthorizationResult authorizeResult)
    {
        var authorizationFailureReason = authorizeResult.AuthorizationFailure?.FailureReasons.FirstOrDefault();
       
        if (authorizationFailureReason?.Handler is FunkyPermissionHandler)
        {
            if (authorizeResult.Forbidden)
            {
                ErrorReport errorReport = new();

                if ( authorizeResult.AuthorizationFailure!.FailureReasons.Any(r => r.Message == FunkyPermissionHandler.FailureReasonBlocked))
                {
                    errorReport.Message = "blocked";
                    errorReport.Url = "~/blocked";
                }

                if (authorizeResult.AuthorizationFailure!.FailureReasons.Any(r => r.Message == FunkyPermissionHandler.FailureReasonNoSiteAccess))
                {
                    errorReport.Message = "no site access";
                    errorReport.Url = "~/noaccess";
                }

                if (authorizeResult.AuthorizationFailure!.FailureReasons.Any(r => r.Message == FunkyPermissionHandler.FailureReasonForceLogout))
                {
                    errorReport.Message = "force logout";
                    errorReport.Url = "~/login";
                }

                context.Response.StatusCode = StatusCodes.Status401Unauthorized;                
                await context.Response.WriteAsJsonAsync(errorReport);           
                
                // return right away as the default implementation would overwrite the status code
                return;
            }
        }

        if(authorizeResult.Succeeded)
        {
            // we can do the cookie stuff here, but need to check the handler, or policy to ensure in this scope
        }

        // Fall back to the default implementation.
        await _handler.HandleAsync(next, context, policy, authorizeResult);
    }
}
