using IdentityEngine.Models.Configuration.Enums;

namespace IdentityEngine.Configuration.Options;

public class ContentSecurityPolicyOptions
{
    public ContentSecurityPolicyLevel Level { get; set; } = ContentSecurityPolicyLevel.Two;

    public bool AddDeprecatedHeader { get; set; } = true;
}
