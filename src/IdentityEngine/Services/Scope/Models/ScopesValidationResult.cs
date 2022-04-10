using System.Diagnostics.CodeAnalysis;
using IdentityEngine.Models.Configuration;

namespace IdentityEngine.Services.Scope.Models;

public class ScopesValidationResult<TIdTokenScope, TAccessTokenScope, TApi, TApiSecret>
    where TIdTokenScope : IIdTokenScope
    where TAccessTokenScope : IAccessTokenScope
    where TApi : IApi<TApiSecret>
    where TApiSecret : ISecret
{
    public ScopesValidationResult(ValidScopes<TIdTokenScope, TAccessTokenScope, TApi, TApiSecret> validScopes)
    {
        ArgumentNullException.ThrowIfNull(validScopes);
        ValidScopes = validScopes;
        HasError = false;
    }

    public ScopesValidationResult(string error)
    {
        if (string.IsNullOrWhiteSpace(error))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(error));
        }

        Error = error;
        HasError = true;
    }

    [MemberNotNullWhen(false, nameof(ValidScopes))]
    [MemberNotNullWhen(true, nameof(Error))]
    public bool HasError { get; }

    public ValidScopes<TIdTokenScope, TAccessTokenScope, TApi, TApiSecret>? ValidScopes { get; }

    public string? Error { get; }
}
