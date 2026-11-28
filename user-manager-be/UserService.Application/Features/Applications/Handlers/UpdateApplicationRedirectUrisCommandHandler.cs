using MediatR;
using UserService.Application.DTOs.Applications;
using UserService.Application.Features.Applications.Commands;
using UserService.Application.Interfaces.Services;
using UserService.Application.Interfaces.Services.Security;
using UserService.Domain.Entities;

namespace UserService.Application.Features.Applications.Handlers;

public sealed class UpdateApplicationRedirectUrisCommandHandler
    : IRequestHandler<UpdateApplicationRedirectUrisCommand, ApplicationCredentialDto>
{
    private readonly IApplicationAppService _applicationService;
    private readonly IAuditLogger _audit;

    public UpdateApplicationRedirectUrisCommandHandler(IApplicationAppService applicationService, IAuditLogger audit)
    {
        _applicationService = applicationService;
        _audit = audit;
    }

    public async Task<ApplicationCredentialDto> Handle(
        UpdateApplicationRedirectUrisCommand request,
        CancellationToken cancellationToken)
    {
        var result = await _applicationService.UpdateRedirectUrisAsync(request.ApplicationId, request.RedirectUris, cancellationToken);
        await _audit.LogAsync(AuditEventTypes.ApplicationRedirectUrisUpdated, true, new AuditEntry(
            TargetType: "application",
            TargetId: request.ApplicationId.ToString(),
            ApplicationId: request.ApplicationId,
            Details: new { redirectUris = result.AllowedRedirectUris }), cancellationToken);
        return result;
    }
}
