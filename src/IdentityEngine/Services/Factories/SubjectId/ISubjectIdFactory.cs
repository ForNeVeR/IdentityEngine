using IdentityEngine.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace IdentityEngine.Services.Factories.SubjectId;

public interface ISubjectIdFactory<TSubjectId>
    where TSubjectId : ISubjectId
{
    Task<TSubjectId> CreateAsync(
        HttpContext httpContext,
        AuthenticationTicket authenticationTicket);
}
