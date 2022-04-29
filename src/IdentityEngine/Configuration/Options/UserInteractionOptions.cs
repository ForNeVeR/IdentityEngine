namespace IdentityEngine.Configuration.Options;

public class UserInteractionOptions
{
    public string ErrorUrl { get; set; } = Constants.Ui.DefaultRoutes.Error;

    public string ErrorIdParameter { get; set; } = Constants.Ui.DefaultRoutesParameters.ErrorId;

    public string AuthorizeRequestId { get; set; } = Constants.Ui.DefaultRoutesParameters.AuthorizeRequestId;

    public string LoginUrl { get; set; } = Constants.Ui.DefaultRoutes.Login;

    public string ConsentUrl { get; set; } = Constants.Ui.DefaultRoutes.Consent;
}
