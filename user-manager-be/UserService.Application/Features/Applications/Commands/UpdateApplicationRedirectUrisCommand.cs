using MediatR;
using UserService.Application.DTOs.Applications;

namespace UserService.Application.Features.Applications.Commands;

public sealed record UpdateApplicationRedirectUrisCommand(
    Guid ApplicationId,
    IReadOnlyList<string> RedirectUris
) : IRequest<ApplicationCredentialDto>;
