namespace IdentityEngine.Models.Default;

public class DefaultSubjectContext : ISubjectContext
{
    public DefaultSubjectContext(string subjectId)
    {
        if (string.IsNullOrWhiteSpace(subjectId))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(subjectId));
        }

        SubjectId = subjectId;
    }

    public string SubjectId { get; }
}
