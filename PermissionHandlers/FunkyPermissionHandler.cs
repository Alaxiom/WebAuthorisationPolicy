using Microsoft.AspNetCore.Authorization;
using WebAuthorisationPolicy.PermissionRequirements;

namespace WebAuthorisationPolicy.PermissionHandlers;

public class FunkyPermissionHandler : IAuthorizationHandler
{
    public const string FailureReasonBlocked = "Blocked";
    public const string FailureReasonNoSiteAccess = "NoSiteAccess";
    public const string FailureReasonForceLogout = "ForceLogout";

    public Task HandleAsync(AuthorizationHandlerContext context)
    {
        // do the stuff with cache for user, roles and application
        // Inject IMemoryCache

        var pendingRequirements = context.PendingRequirements.ToList();

        foreach (var requirement in pendingRequirements)
        {
            if (requirement is NotBlockedAccessRequirement notBlockedRequirement)
            {
                if (!context.User.IsInRole(notBlockedRequirement.BlockedRole))
                {
                    AuthorizationFailureReason failureReason = new(this, FailureReasonBlocked);
                    context.Fail(failureReason);
                }
            }
            else if (requirement is SiteAccessRequirement siteAccessRequirement)
            {
                // look at the roles stored in cache
                AuthorizationFailureReason failureReason = new(this, FailureReasonNoSiteAccess);
                context.Fail(failureReason);
            }
            else if (requirement is ForcedLogoutRequirement forcedLogoutRequirement)
            {
                // compare the sessionid and things
            }
        }

        return Task.CompletedTask;
    }
}

// https://learn.microsoft.com/en-us/aspnet/core/security/authorization/policies?view=aspnetcore-8.0
// NOTE: To ensure other handlers do not report success, a handler could return
// context.Fail();        
// Even when succeed or fail called, all other handlers are still called e.g. logging
// Although:
// When set to false, the InvokeHandlersAfterFailure property short-circuits the execution of
// handlers when context.Fail is called.InvokeHandlersAfterFailure defaults to true, in which
// case all handlers are called.
//
// Handlers can execute in any order, so do not depend on them being called in any particular order.
