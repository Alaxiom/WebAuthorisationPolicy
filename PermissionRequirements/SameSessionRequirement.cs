using Microsoft.AspNetCore.Authorization;

namespace WebAuthorisationPolicy.PermissionRequirements;

public class SameSessionRequirement : IAuthorizationRequirement
{
}
