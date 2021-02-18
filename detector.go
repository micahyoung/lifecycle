package lifecycle

import (
	"fmt"
	"sync"

	"github.com/pkg/errors"

	"github.com/buildpacks/lifecycle/buildpack"
	"github.com/buildpacks/lifecycle/platform"
)

const (
	CodeDetectPass = 0
	CodeDetectFail = 100
)

var (
	ErrFailedDetection = errors.New("no buildpacks participating")
	ErrBuildpack       = errors.New("buildpack(s) failed with err")
)

type Resolver interface {
	Resolve(done []buildpack.GroupBuildpack, detectRuns *sync.Map) ([]buildpack.GroupBuildpack, []platform.BuildPlanEntry, error)
}

type Detector struct {
	buildpack.DetectConfig
	Resolver Resolver
	Runs     *sync.Map
	Store    BuildpackStore
}

func NewDetector(config buildpack.DetectConfig, buildpacksDir string) (*Detector, error) {
	resolver := &DefaultResolver{
		Logger: config.Logger,
	}
	store, err := buildpack.NewBuildpackStore(buildpacksDir)
	if err != nil {
		return nil, err
	}
	return &Detector{
		DetectConfig: config,
		Resolver:     resolver,
		Runs:         &sync.Map{},
		Store:        store,
	}, nil
}

func (d *Detector) Detect(order buildpack.Order) (buildpack.Group, platform.BuildPlan, error) {
	return d.DetectOrder(order)
}

func (d *Detector) DetectOrder(order buildpack.Order) (buildpack.Group, platform.BuildPlan, error) {
	bps, entries, err := d.detectOrder(order, nil, nil, false, &sync.WaitGroup{})
	if err == ErrBuildpack {
		err = buildpack.NewLifecycleError(err, buildpack.ErrTypeBuildpack)
	} else if err == ErrFailedDetection {
		err = buildpack.NewLifecycleError(err, buildpack.ErrTypeFailedDetection)
	}
	for i := range entries {
		for j := range entries[i].Requires {
			entries[i].Requires[j].ConvertVersionToMetadata()
		}
	}
	return buildpack.Group{Group: bps}, platform.BuildPlan{Entries: entries}, err
}

func (d *Detector) detectOrder(order buildpack.Order, done, next []buildpack.GroupBuildpack, optional bool, wg *sync.WaitGroup) ([]buildpack.GroupBuildpack, []platform.BuildPlanEntry, error) {
	ngroup := buildpack.Group{Group: next}
	buildpackErr := false
	for _, group := range order {
		// FIXME: double-check slice safety here
		found, plan, err := d.detectGroup(group.Append(ngroup), done, wg)
		if err == ErrBuildpack {
			buildpackErr = true
		}
		if err == ErrFailedDetection || err == ErrBuildpack {
			wg = &sync.WaitGroup{}
			continue
		}
		return found, plan, err
	}
	if optional {
		return d.detectGroup(ngroup, done, wg)
	}

	if buildpackErr {
		return nil, nil, ErrBuildpack
	}
	return nil, nil, ErrFailedDetection
}

func (d *Detector) detectGroup(group buildpack.Group, done []buildpack.GroupBuildpack, wg *sync.WaitGroup) ([]buildpack.GroupBuildpack, []platform.BuildPlanEntry, error) {
	for i, groupBp := range group.Group {
		key := groupBp.String()
		if hasID(done, groupBp.ID) {
			continue
		}

		bp, err := d.Store.Lookup(groupBp.ID, groupBp.Version)
		if err != nil {
			return nil, nil, err
		}

		bpDesc := bp.ConfigFile()
		groupBp.API = bpDesc.API
		groupBp.Homepage = bpDesc.Buildpack.Homepage

		if bpDesc.IsMetaBuildpack() {
			// TODO: double-check slice safety here
			// FIXME: cyclical references lead to infinite recursion
			return d.detectOrder(bpDesc.Order, done, group.Group[i+1:], groupBp.Optional, wg)
		}
		done = append(done, groupBp)
		wg.Add(1)
		go func(key string, bp Buildpack) {
			if _, ok := d.Runs.Load(key); !ok {
				d.Runs.Store(key, bp.Detect(&d.DetectConfig))
			}
			wg.Done()
		}(key, bp)
	}

	wg.Wait()

	return d.Resolver.Resolve(done, d.Runs)
}

<<<<<<< Updated upstream
func hasID(bps []buildpack.GroupBuildpack, id string) bool {
	for _, bp := range bps {
		if bp.ID == id {
			return true
		}
	}
	return false
}

type DefaultResolver struct {
	Logger Logger
=======
type commandFactory interface {
	NewCommand(cmd string, args ...string) (*exec.Cmd, error)
}

type Provide struct {
	Name string `toml:"name"`
}

type DetectConfig struct {
	FullEnv        []string
	ClearEnv       []string
	AppDir         string
	PlatformDir    string
	BuildpacksDir  string
	Logger         Logger
	CommandFactory commandFactory
	runs           *sync.Map
>>>>>>> Stashed changes
}

// Resolve aggregates the detect output for a group of buildpacks and tries to resolve a build plan for the group.
// If any required buildpack in the group failed detection or a build plan cannot be resolved, it returns an error.
func (r *DefaultResolver) Resolve(done []buildpack.GroupBuildpack, detectRuns *sync.Map) ([]buildpack.GroupBuildpack, []platform.BuildPlanEntry, error) {
	var groupRuns []buildpack.DetectRun
	for _, bp := range done {
		t, ok := detectRuns.Load(bp.String())
		if !ok {
			return nil, nil, errors.Errorf("missing detection of '%s'", bp)
		}
		run := t.(buildpack.DetectRun)
		outputLogf := r.Logger.Debugf

		switch run.Code {
		case CodeDetectPass, CodeDetectFail:
		default:
			outputLogf = r.Logger.Infof
		}

		if len(run.Output) > 0 {
			outputLogf("======== Output: %s ========", bp)
			outputLogf(string(run.Output))
		}
		if run.Err != nil {
			outputLogf("======== Error: %s ========", bp)
			outputLogf(run.Err.Error())
		}
		groupRuns = append(groupRuns, run)
	}

	r.Logger.Debugf("======== Results ========")

	results := detectResults{}
	detected := true
	buildpackErr := false
	for i, bp := range done {
		run := groupRuns[i]
		switch run.Code {
		case CodeDetectPass:
			r.Logger.Debugf("pass: %s", bp)
			results = append(results, detectResult{bp, run})
		case CodeDetectFail:
			if bp.Optional {
				r.Logger.Debugf("skip: %s", bp)
			} else {
				r.Logger.Debugf("fail: %s", bp)
			}
			detected = detected && bp.Optional
		case -1:
			r.Logger.Infof("err:  %s", bp)
			buildpackErr = true
			detected = detected && bp.Optional
		default:
			r.Logger.Infof("err:  %s (%d)", bp, run.Code)
			buildpackErr = true
			detected = detected && bp.Optional
		}
	}
	if !detected {
		if buildpackErr {
			return nil, nil, ErrBuildpack
		}
		return nil, nil, ErrFailedDetection
	}

	i := 0
	deps, trial, err := results.runTrials(func(trial detectTrial) (depMap, detectTrial, error) {
		i++
		return r.runTrial(i, trial)
	})
	if err != nil {
		return nil, nil, err
	}

	if len(done) != len(trial) {
		r.Logger.Infof("%d of %d buildpacks participating", len(trial), len(done))
	}

	maxLength := 0
	for _, t := range trial {
		l := len(t.ID)
		if l > maxLength {
			maxLength = l
		}
	}

	f := fmt.Sprintf("%%-%ds %%s", maxLength)

	for _, t := range trial {
		r.Logger.Infof(f, t.ID, t.Version)
	}

	var found []buildpack.GroupBuildpack
	for _, r := range trial {
		found = append(found, r.GroupBuildpack.NoOpt())
	}
	var plan []platform.BuildPlanEntry
	for _, dep := range deps {
		plan = append(plan, dep.BuildPlanEntry.NoOpt())
	}
	return found, plan, nil
}

func (r *DefaultResolver) runTrial(i int, trial detectTrial) (depMap, detectTrial, error) {
	r.Logger.Debugf("Resolving plan... (try #%d)", i)

	var deps depMap
	retry := true
	for retry {
		retry = false
		deps = newDepMap(trial)

		if err := deps.eachUnmetRequire(func(name string, bp buildpack.GroupBuildpack) error {
			retry = true
			if !bp.Optional {
				r.Logger.Debugf("fail: %s requires %s", bp, name)
				return ErrFailedDetection
			}
			r.Logger.Debugf("skip: %s requires %s", bp, name)
			trial = trial.remove(bp)
			return nil
		}); err != nil {
			return nil, nil, err
		}

		if err := deps.eachUnmetProvide(func(name string, bp buildpack.GroupBuildpack) error {
			retry = true
			if !bp.Optional {
				r.Logger.Debugf("fail: %s provides unused %s", bp, name)
				return ErrFailedDetection
			}
			r.Logger.Debugf("skip: %s provides unused %s", bp, name)
			trial = trial.remove(bp)
			return nil
		}); err != nil {
			return nil, nil, err
		}
	}

	if len(trial) == 0 {
		r.Logger.Debugf("fail: no viable buildpacks in group")
		return nil, nil, ErrFailedDetection
	}
	return deps, trial, nil
}

<<<<<<< Updated upstream
=======
func (b *BuildpackTOML) Detect(c *DetectConfig) DetectRun {
	appDir, err := filepath.Abs(c.AppDir)
	if err != nil {
		return DetectRun{Code: -1, Err: err}
	}
	platformDir, err := filepath.Abs(c.PlatformDir)
	if err != nil {
		return DetectRun{Code: -1, Err: err}
	}
	planDir, err := ioutil.TempDir("", "plan.")
	if err != nil {
		return DetectRun{Code: -1, Err: err}
	}
	defer os.RemoveAll(planDir)

	planPath := filepath.Join(planDir, "plan.toml")
	if err := ioutil.WriteFile(planPath, nil, 0777); err != nil {
		return DetectRun{Code: -1, Err: err}
	}

	out := &bytes.Buffer{}
	cmd, err := c.CommandFactory.NewCommand(
		filepath.Join(b.Dir, "bin", "detect"),
		platformDir,
		planPath,
	)
	if err != nil {
		return DetectRun{Code: -1, Err: errors.Wrap(err, "failed to initialize new command")}
	}
	cmd.Dir = appDir
	cmd.Stdout = out
	cmd.Stderr = out
	cmd.Env = append([]string{}, c.FullEnv...)
	if b.Buildpack.ClearEnv {
		cmd.Env = append([]string{}, c.ClearEnv...)
	}
	cmd.Env = append(cmd.Env, EnvBuildpackDir+"="+b.Dir)

	if err := cmd.Run(); err != nil {
		if err, ok := err.(*exec.ExitError); ok {
			if status, ok := err.Sys().(syscall.WaitStatus); ok {
				return DetectRun{Code: status.ExitStatus(), Output: out.Bytes()}
			}
		}
		return DetectRun{Code: -1, Err: err, Output: out.Bytes()}
	}
	var t DetectRun
	if _, err := toml.DecodeFile(planPath, &t); err != nil {
		return DetectRun{Code: -1, Err: err}
	}
	if api.MustParse(b.API).Equal(api.MustParse("0.2")) {
		if t.hasInconsistentVersions() || t.Or.hasInconsistentVersions() {
			t.Err = errors.Errorf(`buildpack %s has a "version" key that does not match "metadata.version"`, b.Buildpack.ID)
			t.Code = -1
		}
	}
	if api.MustParse(b.API).Compare(api.MustParse("0.3")) >= 0 {
		if t.hasDoublySpecifiedVersions() || t.Or.hasDoublySpecifiedVersions() {
			t.Err = errors.Errorf(`buildpack %s has a "version" key and a "metadata.version" which cannot be specified together. "metadata.version" should be used instead`, b.Buildpack.ID)
			t.Code = -1
		}
	}
	if api.MustParse(b.API).Compare(api.MustParse("0.3")) >= 0 {
		if t.hasTopLevelVersions() || t.Or.hasTopLevelVersions() {
			c.Logger.Warnf(`Warning: buildpack %s has a "version" key. This key is deprecated in build plan requirements in buildpack API 0.3. "metadata.version" should be used instead`, b.Buildpack.ID)
		}
	}
	t.Output = out.Bytes()
	return t
}

type BuildpackGroup struct {
	Group []GroupBuildpack `toml:"group"`
}

func (bg BuildpackGroup) Detect(c *DetectConfig) (BuildpackGroup, BuildPlan, error) {
	if c.runs == nil {
		c.runs = &sync.Map{}
	}
	bps, entries, err := bg.detect(nil, &sync.WaitGroup{}, c)
	if err == errBuildpack {
		err = NewLifecycleError(err, ErrTypeBuildpack)
	} else if err == errFailedDetection {
		err = NewLifecycleError(err, ErrTypeFailedDetection)
	}
	for i := range entries {
		for j := range entries[i].Requires {
			entries[i].Requires[j].convertVersionToMetadata()
		}
	}
	return BuildpackGroup{Group: bps}, BuildPlan{Entries: entries}, err
}

func (bg BuildpackGroup) detect(done []GroupBuildpack, wg *sync.WaitGroup, c *DetectConfig) ([]GroupBuildpack, []BuildPlanEntry, error) {
	for i, bp := range bg.Group {
		key := bp.String()
		if hasID(done, bp.ID) {
			continue
		}
		info, err := bp.Lookup(c.BuildpacksDir)
		if err != nil {
			return nil, nil, err
		}
		bp.API = info.API
		bp.Homepage = info.Buildpack.Homepage
		if info.Order != nil {
			// TODO: double-check slice safety here
			// FIXME: cyclical references lead to infinite recursion
			return info.Order.detect(done, bg.Group[i+1:], bp.Optional, wg, c)
		}
		done = append(done, bp)
		wg.Add(1)
		go func(key string, info *BuildpackTOML) {
			if _, ok := c.runs.Load(key); !ok {
				c.runs.Store(key, info.Detect(c))
			}
			wg.Done()
		}(key, info)
	}

	wg.Wait()

	return c.process(done)
}

func (bg BuildpackGroup) append(group ...BuildpackGroup) BuildpackGroup {
	for _, g := range group {
		bg.Group = append(bg.Group, g.Group...)
	}
	return bg
}

type BuildpackOrder []BuildpackGroup

func (bo BuildpackOrder) Detect(c *DetectConfig) (BuildpackGroup, BuildPlan, error) {
	if c.runs == nil {
		c.runs = &sync.Map{}
	}
	bps, entries, err := bo.detect(nil, nil, false, &sync.WaitGroup{}, c)
	if err == errBuildpack {
		err = NewLifecycleError(err, ErrTypeBuildpack)
	} else if err == errFailedDetection {
		err = NewLifecycleError(err, ErrTypeFailedDetection)
	}
	for i := range entries {
		for j := range entries[i].Requires {
			entries[i].Requires[j].convertVersionToMetadata()
		}
	}
	return BuildpackGroup{Group: bps}, BuildPlan{Entries: entries}, err
}

func (bo BuildpackOrder) detect(done, next []GroupBuildpack, optional bool, wg *sync.WaitGroup, c *DetectConfig) ([]GroupBuildpack, []BuildPlanEntry, error) {
	ngroup := BuildpackGroup{Group: next}
	buildpackErr := false
	for _, group := range bo {
		// FIXME: double-check slice safety here
		found, plan, err := group.append(ngroup).detect(done, wg, c)
		if err == errBuildpack {
			buildpackErr = true
		}
		if err == errFailedDetection || err == errBuildpack {
			wg = &sync.WaitGroup{}
			continue
		}
		return found, plan, err
	}
	if optional {
		return ngroup.detect(done, wg, c)
	}

	if buildpackErr {
		return nil, nil, errBuildpack
	}
	return nil, nil, errFailedDetection
}

func hasID(bps []GroupBuildpack, id string) bool {
	for _, bp := range bps {
		if bp.ID == id {
			return true
		}
	}
	return false
}

type DetectRun struct {
	planSections
	Or     planSectionsList `toml:"or"`
	Output []byte           `toml:"-"`
	Code   int              `toml:"-"`
	Err    error            `toml:"-"`
}

type planSections struct {
	Requires []Require `toml:"requires"`
	Provides []Provide `toml:"provides"`
}

func (p *planSections) hasInconsistentVersions() bool {
	for _, req := range p.Requires {
		if req.hasInconsistentVersions() {
			return true
		}
	}
	return false
}

func (p *planSections) hasDoublySpecifiedVersions() bool {
	for _, req := range p.Requires {
		if req.hasDoublySpecifiedVersions() {
			return true
		}
	}
	return false
}

func (p *planSections) hasTopLevelVersions() bool {
	for _, req := range p.Requires {
		if req.hasTopLevelVersions() {
			return true
		}
	}
	return false
}

type planSectionsList []planSections

func (p *planSectionsList) hasInconsistentVersions() bool {
	for _, planSection := range *p {
		if planSection.hasInconsistentVersions() {
			return true
		}
	}
	return false
}

func (p *planSectionsList) hasDoublySpecifiedVersions() bool {
	for _, planSection := range *p {
		if planSection.hasDoublySpecifiedVersions() {
			return true
		}
	}
	return false
}

func (p *planSectionsList) hasTopLevelVersions() bool {
	for _, planSection := range *p {
		if planSection.hasTopLevelVersions() {
			return true
		}
	}
	return false
}

>>>>>>> Stashed changes
type detectResult struct {
	buildpack.GroupBuildpack
	buildpack.DetectRun
}

func (r *detectResult) options() []detectOption {
	var out []detectOption
	for i, sections := range append([]buildpack.PlanSections{r.PlanSections}, r.Or...) {
		bp := r.GroupBuildpack
		bp.Optional = bp.Optional && i == len(r.Or)
		out = append(out, detectOption{bp, sections})
	}
	return out
}

type detectResults []detectResult
type trialFunc func(detectTrial) (depMap, detectTrial, error)

func (rs detectResults) runTrials(f trialFunc) (depMap, detectTrial, error) {
	return rs.runTrialsFrom(nil, f)
}

func (rs detectResults) runTrialsFrom(prefix detectTrial, f trialFunc) (depMap, detectTrial, error) {
	if len(rs) == 0 {
		deps, trial, err := f(prefix)
		return deps, trial, err
	}

	var lastErr error
	for _, option := range rs[0].options() {
		deps, trial, err := rs[1:].runTrialsFrom(append(prefix, option), f)
		if err == nil {
			return deps, trial, nil
		}
		lastErr = err
	}
	return nil, nil, lastErr
}

type detectOption struct {
	buildpack.GroupBuildpack
	buildpack.PlanSections
}

type detectTrial []detectOption

func (ts detectTrial) remove(bp buildpack.GroupBuildpack) detectTrial {
	var out detectTrial
	for _, t := range ts {
		if t.GroupBuildpack != bp {
			out = append(out, t)
		}
	}
	return out
}

type depEntry struct {
	platform.BuildPlanEntry
	earlyRequires []buildpack.GroupBuildpack
	extraProvides []buildpack.GroupBuildpack
}

type depMap map[string]depEntry

func newDepMap(trial detectTrial) depMap {
	m := depMap{}
	for _, option := range trial {
		for _, p := range option.Provides {
			m.provide(option.GroupBuildpack, p)
		}
		for _, r := range option.Requires {
			m.require(option.GroupBuildpack, r)
		}
	}
	return m
}

func (m depMap) provide(bp buildpack.GroupBuildpack, provide buildpack.Provide) {
	entry := m[provide.Name]
	entry.extraProvides = append(entry.extraProvides, bp)
	m[provide.Name] = entry
}

func (m depMap) require(bp buildpack.GroupBuildpack, require buildpack.Require) {
	entry := m[require.Name]
	entry.Providers = append(entry.Providers, entry.extraProvides...)
	entry.extraProvides = nil

	if len(entry.Providers) == 0 {
		entry.earlyRequires = append(entry.earlyRequires, bp)
	} else {
		entry.Requires = append(entry.Requires, require)
	}
	m[require.Name] = entry
}

func (m depMap) eachUnmetProvide(f func(name string, bp buildpack.GroupBuildpack) error) error {
	for name, entry := range m {
		if len(entry.extraProvides) != 0 {
			for _, bp := range entry.extraProvides {
				if err := f(name, bp); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (m depMap) eachUnmetRequire(f func(name string, bp buildpack.GroupBuildpack) error) error {
	for name, entry := range m {
		if len(entry.earlyRequires) != 0 {
			for _, bp := range entry.earlyRequires {
				if err := f(name, bp); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
