package collectors

import (
	"strings"
	"time"

	"github.com/responseray/collector-macos/internal/fsutil"
)

type UserCollector struct{}

func (UserCollector) Name() string { return "Users" }

func (UserCollector) Run(ctx *fsutil.Context) error {
	out := map[string]interface{}{}

	if v, err := runCmd(15*time.Second, "dscl", ".", "list", "/Users"); err == nil {
		out["dscl_users"] = strings.Split(strings.TrimSpace(v), "\n")
	}
	if v, err := runCmd(15*time.Second, "dscl", ".", "list", "/Groups"); err == nil {
		out["dscl_groups"] = strings.Split(strings.TrimSpace(v), "\n")
	}
	if v, err := runCmd(15*time.Second, "dscl", ".", "-readall", "/Users", "RecordName", "RealName", "UniqueID", "PrimaryGroupID", "NFSHomeDirectory", "UserShell", "AuthenticationAuthority", "AccountPolicyData"); err == nil {
		out["dscl_user_records"] = v
	}
	if v, err := runCmd(15*time.Second, "last"); err == nil {
		out["last"] = v
	}
	if v, err := runCmd(10*time.Second, "who"); err == nil {
		out["who"] = v
	}
	if v, err := runCmd(10*time.Second, "id"); err == nil {
		out["whoami_id"] = v
	}
	if v, err := runCmd(10*time.Second, "groups"); err == nil {
		out["groups_current"] = v
	}
	if v, err := runCmd(10*time.Second, "dscacheutil", "-q", "user"); err == nil {
		out["dscacheutil_users"] = v
	}

	out["user_homes"] = userHomes()

	if _, err := ctx.WriteJSON("live/users.json", "users", out); err != nil {
		return err
	}
	return nil
}
