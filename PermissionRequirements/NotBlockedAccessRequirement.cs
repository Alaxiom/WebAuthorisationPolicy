using Microsoft.AspNetCore.Authorization;

namespace WebAuthorisationPolicy.PermissionRequirements;

public class NotBlockedAccessRequirement : IAuthorizationRequirement
{
    public string BlockedRole { get; }
    public NotBlockedAccessRequirement(string application, string role) =>
        BlockedRole = $"{application}_{role}";
}
