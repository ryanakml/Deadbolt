import type { AuthSession } from "./api.js";
import type { RunStatus } from "./types.js";
export declare const RUNS_CONTROL_CAPABILITY = "runs:control";
export declare const APPROVALS_DECIDE_CAPABILITY = "approvals:decide";
export declare const SCHEDULES_WRITE_CAPABILITY = "schedules:write";
export declare function roleCanManageSchedules(role: string | null | undefined): boolean;
export declare function sessionCanManageSchedules(session: AuthSession | null | undefined, orgId: string | null | undefined): boolean;
export declare function roleCanDecideApprovals(role: string | null | undefined): boolean;
export declare function sessionCanDecideApprovals(session: AuthSession | null | undefined, orgId: string | null | undefined): boolean;
export declare function roleCanControlRuns(role: string | null | undefined): boolean;
export declare function sessionCanControlRuns(session: AuthSession | null | undefined, orgId: string | null | undefined): boolean;
export interface RunControlVisibility {
    pause: boolean;
    resume: boolean;
    cancel: boolean;
}
export declare function visibleRunControls(status: RunStatus, canControl: boolean): RunControlVisibility;
export declare const WORKERS_DRAIN_CAPABILITY = "workers:drain";
export declare function roleCanDrainWorkers(role: string | null | undefined): boolean;
export declare function sessionCanDrainWorkers(session: AuthSession | null | undefined, orgId: string | null | undefined): boolean;
export declare const WEBHOOKS_WRITE_CAPABILITY = "webhooks:write";
export declare function roleCanManageWebhooks(role: string | null | undefined): boolean;
export declare function sessionCanManageWebhooks(session: AuthSession | null | undefined, orgId: string | null | undefined): boolean;
export declare function visibleRerunControl(status: RunStatus, canControl: boolean): boolean;
export declare const ADMIN_MEMBER_CAPABILITY = "admin:member";
export declare function roleCanManageMembers(role: string | null | undefined): boolean;
export declare function sessionCanManageMembers(session: AuthSession | null | undefined, orgId: string | null | undefined): boolean;
export declare const ADMIN_KEY_CAPABILITY = "admin:key";
export declare function roleCanManageKeys(role: string | null | undefined): boolean;
export declare function sessionCanManageKeys(session: AuthSession | null | undefined, orgId: string | null | undefined): boolean;
export declare const PAYLOAD_READ_CAPABILITY = "payload:read";
export declare function roleCanReadPayload(role: string | null | undefined): boolean;
export declare function sessionCanReadPayload(session: AuthSession | null | undefined, orgId: string | null | undefined): boolean;
//# sourceMappingURL=permissions.d.ts.map