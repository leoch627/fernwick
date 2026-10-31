package core

import "testing"

func TestIdentityUsesStableProductNames(t *testing.T) {
	build := BuildConfig{ProductID: "moon-cloud", AppID: "app.moon-cloud", Name: "新名字"}
	if HelperSocket(build, "linux") != "/run/moon-cloud/helper.sock" || HelperSocket(build, "win32") != `\\.\pipe\moon-cloud.helper.v1` || HelperRoot(build, `C:\Program Files\新名字`, "win32") != `C:\Program Files\moon-cloud-service` || HelperRoot(build, "/Applications/新名字.app", "darwin") != "/Library/PrivilegedHelperTools/app.moon-cloud.helper" {
		t.Fatal("unstable helper identity")
	}
	for _, value := range []string{"../evil", "UPPER", "a", "aa", "-bad", "bad-"} {
		if ValidProductID(value) {
			t.Errorf("unsafe product ID accepted: %q", value)
		}
	}
	for _, value := range []string{"../app", "app", "app.bad/other", "App.good"} {
		if ValidAppID(value) {
			t.Errorf("unsafe app ID accepted: %q", value)
		}
	}
	for _, value := range []string{"a/b", "a\\b", "$(id)", "a\nb", "a\"b", "a'b", "a`b", "a&b"} {
		if ValidDisplayName(value) {
			t.Errorf("unsafe display name accepted: %q", value)
		}
	}
	if !ValidDisplayName("新名字") || !ValidProductID(build.ProductID) || !ValidAppID(build.AppID) {
		t.Fatal("valid identity rejected")
	}
}
