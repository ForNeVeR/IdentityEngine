namespace IdentityEngine.Configuration.Options;

public class UserInteractionOptions
{
    public string ErrorUrl { get; set; } = Constants.Ui.DefaultRoutes.Error;

    public string ErrorIdParameter { get; set; } = Constants.Ui.DefaultRoutesParameters.ErrorId;
}
