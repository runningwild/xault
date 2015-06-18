package xault

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestDualKeys(t *testing.T) {
	Convey("something", t, func() {
		var ls0, ls1 LifetimeState
		So(ls0.SetRootDir("."), ShouldBeNil)
		So(ls0.MakeKeys("this is a name"), ShouldBeNil)
		defer func() {
			So(ls0.DestroyKeys(), ShouldBeNil)
		}()
		So(ls1.SetRootDir("."), ShouldBeNil)
		So(ls1.LoadKeys(), ShouldBeNil)

		So(ls1.info.Id, ShouldEqual, ls0.info.Id)
		So(ls1.info.Name, ShouldEqual, ls0.info.Name)
		So(ls1.info.Server, ShouldEqual, ls0.info.Server)
		So(ls1.key.D0.Cmp(ls0.key.D0), ShouldEqual, 0)
		So(ls1.key.D1.Cmp(ls0.key.D1), ShouldEqual, 0)
		So(ls1.key.P.Cmp(ls0.key.P), ShouldEqual, 0)
		So(ls1.key.Q.Cmp(ls0.key.Q), ShouldEqual, 0)
	})
}
