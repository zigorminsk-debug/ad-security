namespace AdTrustRepair.Models;

public enum ResetMethod
{
    /// <summary>Reset-ComputerMachinePassword — штатный сброс пароля в AD и локально (нужны права).</summary>
    ResetComputerMachinePassword,
    /// <summary>Test-ComputerSecureChannel -Repair — штатное восстановление канала.</summary>
    SecureChannelRepair,
    /// <summary>netdom resetpwd — требует учётную запись администратора домена.</summary>
    Netdom,
    /// <summary>Экспертный: чтение секрета LSA и сброс через NetUserSetInfo.</summary>
    LsaNetUser,
    /// <summary>ksetup /setcomputerpassword — резервный способ, может нарушить машинный ключ TPM.</summary>
    Ksetup
}

public sealed class RepairOptions
{
    public ResetMethod PreferredMethod { get; set; } = ResetMethod.ResetComputerMachinePassword;
    public bool AllowFallbackMethods { get; set; } = true;
    public bool ResetMachinePassword { get; set; } = true;
    public bool PurgeKerberosTickets { get; set; } = true;
    public bool FlushDns { get; set; } = true;
    public bool RestartNetlogon { get; set; } = true;
    public bool ForceGroupPolicy { get; set; }
    public bool DsregLeaveBeforeKsetup { get; set; } = true;
    public string? DomainAdminUser { get; set; }
    public string? DomainAdminPassword { get; set; }
    public bool VerifyAfterRepair { get; set; } = true;
}

public sealed class RepairStepResult
{
    public string Title { get; init; } = "";
    public bool Success { get; init; }
    public bool Skipped { get; init; }
    public string Message { get; init; } = "";
}

public sealed class RepairReport
{
    public DateTime StartedLocal { get; set; } = DateTime.Now;
    public DateTime FinishedLocal { get; set; } = DateTime.Now;
    public List<RepairStepResult> Steps { get; } = new();
    public bool MachinePasswordReset { get; set; }
    public string? MethodUsed { get; set; }
    public bool? TrustRestored { get; set; }
    public string? VerificationMessage { get; set; }
    public string? NewPassword { get; set; }
    public string? ErrorMessage { get; set; }

    public bool Succeeded => TrustRestored == true;
}
