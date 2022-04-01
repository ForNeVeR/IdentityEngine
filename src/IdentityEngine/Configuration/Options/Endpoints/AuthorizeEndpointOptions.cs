namespace IdentityEngine.Configuration.Options.Endpoints;

public class AuthorizeEndpointOptions
{
    public bool Enable { get; set; } = true;
    public string Path { get; set; } = Constants.Ui.DefaultRoutes.Authorize;
    public string CallbackPath { get; set; } = Constants.Ui.DefaultRoutes.AuthorizeCallback;
}
