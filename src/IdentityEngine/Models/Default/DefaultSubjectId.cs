namespace IdentityEngine.Models.Default;

public class DefaultSubjectId : ISubjectId
{
    public DefaultSubjectId(string subjectId)
    {
        if (string.IsNullOrWhiteSpace(subjectId))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(subjectId));
        }

        SubjectId = subjectId;
    }

    public string SubjectId { get; }
}
