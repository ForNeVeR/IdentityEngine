namespace IdentityEngine.Configuration.Options;

public class InputLengthRestrictionsOptions
{
    /// <summary>
    ///     Max length for "client_id".
    /// </summary>
    public int ClientId { get; set; } = 100;

    /// <summary>
    ///     Max length for "state".
    /// </summary>
    public int State { get; set; } = 2000;

    /// <summary>
    ///     Max length for "redirect_uri".
    /// </summary>
    public int RedirectUri { get; set; } = 400;

    /// <summary>
    ///     Max length for "scope".
    /// </summary>
    public int Scope { get; set; } = 300;

    /// <summary>
    ///     Min length for "code_challenge". https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#appendix-A.18
    /// </summary>
    public int CodeChallengeMinLength { get; set; } = 43;

    /// <summary>
    ///     Min length for "code_challenge". https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#appendix-A.18
    /// </summary>
    public int CodeChallengeMaxLength { get; set; } = 128;

    /// <summary>
    ///     Max length for "nonce".
    /// </summary>
    public int Nonce { get; set; } = 300;

    /// <summary>
    ///     Max length for "login_hint".
    /// </summary>
    public int LoginHint { get; set; } = 100;

    /// <summary>
    ///     Max length for "acr_values".
    /// </summary>
    public int AcrValues { get; set; } = 300;

    /// <summary>
    ///     Max length for "ui_locales".
    /// </summary>
    public int UiLocales { get; set; } = 100;
}
