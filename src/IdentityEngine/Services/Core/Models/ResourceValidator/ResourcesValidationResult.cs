using System.Diagnostics.CodeAnalysis;
using IdentityEngine.Models.Configuration;

namespace IdentityEngine.Services.Core.Models.ResourceValidator;

public class ResourcesValidationResult<TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret>
    where TIdTokenScope : class, IIdTokenScope
    where TAccessTokenScope : class, IAccessTokenScope
    where TResource : class, IResource<TResourceSecret>
    where TResourceSecret : class, ISecret
{
    public ResourcesValidationResult(ValidResources<TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret> valid)
    {
        ArgumentNullException.ThrowIfNull(valid);
        HasError = false;
        HasMisconfigured = false;
        Valid = valid;
    }

    public ResourcesValidationResult(MisconfiguredResources misconfigured)
    {
        ArgumentNullException.ThrowIfNull(misconfigured);
        HasError = true;
        HasMisconfigured = true;
        Misconfigured = misconfigured;
    }

    public ResourcesValidationResult(IReadOnlySet<string> invalid)
    {
        ArgumentNullException.ThrowIfNull(invalid);
        HasError = true;
        HasMisconfigured = false;
        Invalid = invalid;
    }

    [MemberNotNullWhen(false, nameof(Valid))]
    public bool HasError { get; }

    [MemberNotNullWhen(true, nameof(Misconfigured))]
    [MemberNotNullWhen(false, nameof(Invalid))]
    public bool HasMisconfigured { get; }

    public ValidResources<TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret>? Valid { get; }

    public IReadOnlySet<string>? Invalid { get; }

    public MisconfiguredResources? Misconfigured { get; }
}
