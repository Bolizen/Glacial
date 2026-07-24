import React, { useEffect, useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  activityDetail,
  activityTimeLabel,
  activityTitle,
  groupActivityByDate,
  normalizeActivityPage,
} from "./activity.js";
import { requestApi } from "./apiTransport.js";
import {
  dependencyStatusDescription,
  dependencyStatusLabel,
  dependencyTrustHasNoSupportedMetadata,
  normalizeDependencyTrust,
} from "./dependencyTrust.js";
import { applyFindingReviewToScan, findingReviewLabel, findingReviewSummary } from "./findingReviews.js";
import {
  buildFindingWorkbenchItems,
  filterFindingWorkbenchItems,
  findingWorkbenchFilterOptions,
  findingWorkbenchProgress,
  nextUnresolvedFindingKey,
} from "./findingWorkbench.js";
import {
  buildGuidedReviewState,
  dismissGuidedReview,
  readGuidedReviewDismissals,
} from "./guidedReview.js";
import { ProjectExpectationsPanel } from "./ProjectExpectations.jsx";
import {
  EMPTY_PROJECT_EXPECTATIONS,
  normalizeProjectExpectations,
} from "./projectExpectations.js";
import { buildProjectDriftSummary } from "./projectDrift.js";
import { shortBaselineFingerprint, trustedBaselineComparisonLabel } from "./trustedDependencyBaseline.js";
import {
  isAbortError,
  projectListResponsePolicy,
  requestIsCurrent,
  scopedRequestIsCurrent,
  shouldReloadSelectedProjectAfterMutation,
} from "./projectRequests.js";
import { buildScanReportMarkdown, normalizeFinding, normalizeScanCompleteness, SCAN_GUIDANCE } from "./reportMarkdown.js";
import {
  clearSessionState,
  readSessionState,
  serializeSessionState,
  stateForWorkspace,
  writeSessionState,
} from "./sessionState.js";
import glacialIcon from "../src-tauri/icons/128x128.png";
import "./styles.css";

const TRANSIENT_NOTICE_MS = 4000;
const EMPTY_AGENT_FORM = {
  project_purpose: "",
  project_rules: "",
  build_commands: "",
  test_commands: "",
  security_notes: "",
};
const MAJOR_SECTIONS = ["changelog", "scanReport", "agents", "notes", "history"];
const OPEN_MAJOR_SECTIONS = Object.fromEntries(MAJOR_SECTIONS.map((section) => [section, true]));
const PROJECT_REQUIRED_SECTIONS = new Set(["trustProfiles", "activity", "reports"]);
const SECTION_NAV = [
  { id: "workspace", href: "#workspace-overview", label: "Workspace Overview", icon: "#" },
  { id: "projects", href: "#projects", label: "Projects", icon: "[]" },
  { id: "trustProfiles", href: "#project-expectations", label: "Project Expectations", icon: "<>" },
  { id: "activity", href: "#activity", label: "Activity", icon: "::" },
  { id: "reports", href: "#reports", label: "Reports", icon: "=" },
  { id: "changelog", href: "#changelog", label: "Changelog", icon: "@" },
  { id: "settings", href: "#settings", label: "Settings", icon: "*" },
];
const TRUST_PROFILE_FIELDS = [
  "trustedPackageManagers",
  "expectedManifestFiles",
  "expectedLockfiles",
  "allowedLifecycleScripts",
  "expectedEcosystems",
  "reviewedPaths",
  "ignoredPaths",
];
const EMPTY_TRUST_PROFILE = EMPTY_PROJECT_EXPECTATIONS;
const EMPTY_ACTIVITY_STATE = Object.freeze({
  events: [],
  hasMore: false,
  nextOffset: null,
  loading: false,
  error: "",
});
export function App() {
  const [projectRoot, setProjectRoot] = useState("");
  const [projectRootMessage, setProjectRootMessage] = useState("");
  const [projects, setProjects] = useState([]);
  const [selectedPath, setSelectedPath] = useState("");
  const [loading, setLoading] = useState(true);
  const [projectDetailsLoading, setProjectDetailsLoading] = useState(false);
  const [message, setMessage] = useState("");
  const [createForm, setCreateForm] = useState({ project_name: "", existing_path: "", description: "", project_type: "" });
  const [agentForm, setAgentForm] = useState(EMPTY_AGENT_FORM);
  const [agentPreview, setAgentPreview] = useState("");
  const [agentsExists, setAgentsExists] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [scanHistory, setScanHistory] = useState([]);
  const [selectedScanId, setSelectedScanId] = useState(null);
  const [trustProfile, setTrustProfile] = useState(EMPTY_TRUST_PROFILE);
  const [trustProfileMessage, setTrustProfileMessage] = useState("");
  const [activity, setActivity] = useState(EMPTY_ACTIVITY_STATE);
  const [notes, setNotes] = useState([]);
  const [noteBody, setNoteBody] = useState("");
  const [changelog, setChangelog] = useState([]);
  const [majorSectionsOpen, setMajorSectionsOpen] = useState(OPEN_MAJOR_SECTIONS);
  const [copyStatus, setCopyStatus] = useState("");
  const [createProjectOpen, setCreateProjectOpen] = useState(false);
  const [selectedSection, setSelectedSection] = useState("workspace");
  const [projectDetailsRevision, setProjectDetailsRevision] = useState(0);
  const [isScanning, setIsScanning] = useState(false);
  const [backendHealth, setBackendHealth] = useState("checking");
  const [workspaceRootChanging, setWorkspaceRootChanging] = useState(false);
  const [workspaceRootError, setWorkspaceRootError] = useState("");
  const [metadataSaving, setMetadataSaving] = useState(false);
  const [unregisteringPath, setUnregisteringPath] = useState("");
  const [findingReviewState, setFindingReviewState] = useState({});
  const [trustedBaselineMutation, setTrustedBaselineMutation] = useState({ saving: false, error: "", success: "" });
  const [sessionStateReady, setSessionStateReady] = useState(false);
  const [dismissedGuidedReviews, setDismissedGuidedReviews] = useState(() => readGuidedReviewDismissals());
  const [toastTop, setToastTop] = useState(112);
  const topbarRef = useRef(null);
  const selectedPathRef = useRef("");
  const projectGenerationRef = useRef(0);
  const projectsRequestRef = useRef({ id: 0, controller: null });
  const workspaceRequestRef = useRef(0);
  const workspaceGenerationRef = useRef(0);
  const unregisterRequestRef = useRef(0);
  const scanningRef = useRef(false);
  const initialSessionStateRef = useRef(undefined);
  const restorationPendingRef = useRef(true);
  const pendingScanRestoreRef = useRef(null);
  const skipNextSessionWriteRef = useRef(false);
  const lastSessionWriteRef = useRef("");
  const findingReviewRequestsRef = useRef(new Map());
  const trustedBaselineRequestRef = useRef({ id: 0, controller: null });
  if (initialSessionStateRef.current === undefined) initialSessionStateRef.current = readSessionState();
  const projectRequestsByScopeRef = useRef({
    notes: 0,
    scanHistory: 0,
    trustProfile: 0,
    activity: 0,
    agentsExists: 0,
    scanMutation: 0,
    noteMutation: 0,
    agentPreview: 0,
    agentWrite: 0,
    trustSave: 0,
    metadataSave: 0,
    trustedBaselineMutation: 0,
  });

  const selectedProject = useMemo(
    () => projects.find((project) => project.path === selectedPath) || null,
    [projects, selectedPath],
  );
  const selectedHistoryScan = useMemo(
    () => scanHistory.find((scan) => scan.id === selectedScanId) || null,
    [scanHistory, selectedScanId],
  );
  const displayedScan = selectedHistoryScan || scanResult || scanHistory[0] || null;
  const scanViewMode = selectedHistoryScan ? "history" : "latest";
  const displayedReport = useMemo(() => buildScanReport(displayedScan), [displayedScan]);
  const displayedComparison = useMemo(() => buildScanComparisonFor(displayedScan, scanHistory), [displayedScan, scanHistory]);
  const displayedTrustContext = useMemo(() => buildTrustProfileContext(displayedReport, trustProfile), [displayedReport, trustProfile]);
  const displayedProjectDrift = useMemo(
    () => buildProjectDriftSummary({ scans: scanHistory, profile: trustProfile, currentScanId: displayedScan?.id }),
    [scanHistory, trustProfile, displayedScan?.id],
  );
  const displayedReportMarkdown = useMemo(
    () => (displayedScan ? buildScanReportMarkdown(
      displayedScan,
      displayedReport,
      displayedComparison,
      displayedTrustContext,
      displayedProjectDrift,
    ) : ""),
    [displayedScan, displayedReport, displayedComparison, displayedTrustContext, displayedProjectDrift],
  );
  const latestProjectScan = scanResult || scanHistory[0] || null;
  const latestProjectReport = useMemo(() => buildScanReport(latestProjectScan), [latestProjectScan]);
  const latestGuidedReview = useMemo(() => buildGuidedReviewState({
    project: selectedProject,
    scan: latestProjectScan,
    completeness: latestProjectReport.completeness,
    dependencyTrust: latestProjectReport.dependencyTrust,
  }), [selectedProject, latestProjectScan, latestProjectReport]);
  const displayedGuidedReview = useMemo(() => buildGuidedReviewState({
    project: selectedProject,
    scan: displayedScan,
    completeness: displayedReport.completeness,
    dependencyTrust: displayedReport.dependencyTrust,
  }), [selectedProject, displayedScan, displayedReport]);
  const selectedSectionInfo = SECTION_NAV.find((section) => section.id === selectedSection) || SECTION_NAV[0];

  useEffect(() => {
    refreshProjects();
    loadChangelog();
    checkHealth();
  }, []);

  useEffect(() => () => trustedBaselineRequestRef.current.controller?.abort(), []);

  useEffect(() => {
    if (!selectedPath) {
      setProjectDetailsLoading(false);
      return undefined;
    }

    const generation = projectGenerationRef.current;
    const controller = new AbortController();
    Promise.allSettled([
      loadNotes(selectedPath, generation, controller.signal),
      loadScanHistory(selectedPath, generation, controller.signal),
      loadTrustProfile(selectedPath, generation, controller.signal),
      loadActivity(selectedPath, generation, controller.signal),
      checkAgentsExists(selectedPath, generation, controller.signal),
    ]).then(() => {
      if (!controller.signal.aborted && projectRequestIsCurrent(selectedPath, generation)) {
        setProjectDetailsLoading(false);
      }
    });
    return () => controller.abort();
  }, [selectedPath, projectDetailsRevision]);

  useEffect(() => {
    setCopyStatus("");
  }, [displayedScan?.id]);

  useEffect(() => {
    if (!copyStatus) return undefined;
    const timeout = setTimeout(() => setCopyStatus(""), TRANSIENT_NOTICE_MS);
    return () => clearTimeout(timeout);
  }, [copyStatus]);

  useEffect(() => {
    if (!isTransientSuccessMessage(message)) return undefined;
    const timeout = setTimeout(() => setMessage(""), TRANSIENT_NOTICE_MS);
    return () => clearTimeout(timeout);
  }, [message]);

  useEffect(() => {
    const topbar = topbarRef.current;
    if (!topbar) return undefined;
    const updateToastTop = () => {
      const viewportInset = window.innerWidth <= 620 ? 14 : 28;
      setToastTop(Math.max(viewportInset, Math.ceil(topbar.getBoundingClientRect().bottom) + 12));
    };
    updateToastTop();
    window.addEventListener("resize", updateToastTop);
    window.addEventListener("scroll", updateToastTop, { passive: true });
    const observer = window.ResizeObserver ? new window.ResizeObserver(updateToastTop) : null;
    observer?.observe(topbar);
    return () => {
      observer?.disconnect();
      window.removeEventListener("resize", updateToastTop);
      window.removeEventListener("scroll", updateToastTop);
    };
  }, []);

  useEffect(() => {
    if (!sessionStateReady || !projectRoot) return;
    if (pendingScanRestoreRef.current) return;
    const snapshot = sessionSnapshot();
    const serialized = serializeSessionState(snapshot);
    if (!serialized) return;
    if (skipNextSessionWriteRef.current) {
      skipNextSessionWriteRef.current = false;
      lastSessionWriteRef.current = serialized;
      return;
    }
    if (serialized === lastSessionWriteRef.current) return;
    lastSessionWriteRef.current = serialized;
    writeSessionState(snapshot);
  }, [sessionStateReady, projectRoot, selectedPath, selectedSection, selectedScanId, majorSectionsOpen]);

  function resetProjectState(path) {
    setMessage("");
    setProjectDetailsLoading(Boolean(path));
    setAgentForm(EMPTY_AGENT_FORM);
    setAgentPreview("");
    setAgentsExists(false);
    setScanResult(null);
    setScanHistory([]);
    setSelectedScanId(null);
    setTrustProfile({ ...EMPTY_TRUST_PROFILE, project_path: path });
    setTrustProfileMessage("");
    setActivity(EMPTY_ACTIVITY_STATE);
    setNotes([]);
    setNoteBody("");
    setCopyStatus("");
    scanningRef.current = false;
    setIsScanning(false);
    setMetadataSaving(false);
    findingReviewRequestsRef.current.clear();
    setFindingReviewState({});
    trustedBaselineRequestRef.current.controller?.abort();
    trustedBaselineRequestRef.current = { id: trustedBaselineRequestRef.current.id + 1, controller: null };
    setTrustedBaselineMutation({ saving: false, error: "", success: "" });
  }

  function selectProject(path, { restoring = false, force = false } = {}) {
    const nextPath = path || "";
    const sameProject = selectedPathRef.current === nextPath;
    if (!restoring) pendingScanRestoreRef.current = null;
    if (!force && sameProject) return;
    selectedPathRef.current = nextPath;
    projectGenerationRef.current += 1;
    resetProjectState(nextPath);
    setSelectedPath(nextPath);
    if (force && sameProject && nextPath) setProjectDetailsRevision((revision) => revision + 1);
  }

  function projectRequestIsCurrent(path, generation) {
    return requestIsCurrent(
      selectedPathRef.current,
      projectGenerationRef.current,
      path,
      generation,
    );
  }

  function beginScopedProjectRequest(scope) {
    const requestId = projectRequestsByScopeRef.current[scope] + 1;
    projectRequestsByScopeRef.current[scope] = requestId;
    return requestId;
  }

  function scopedProjectRequestIsCurrent(scope, requestId, path, generation) {
    return scopedRequestIsCurrent(
      projectRequestsByScopeRef.current[scope],
      requestId,
      selectedPathRef.current,
      projectGenerationRef.current,
      path,
      generation,
    );
  }

  function reloadSelectedProjectAfterStaleMutation(path, generation) {
    const shouldReload = shouldReloadSelectedProjectAfterMutation(
      selectedPathRef.current,
      projectGenerationRef.current,
      path,
      generation,
    );
    if (!shouldReload) return;

    projectGenerationRef.current += 1;
    setProjectDetailsLoading(true);
    setProjectDetailsRevision((revision) => revision + 1);
  }

  async function refreshProjects(
    requestPath = null,
    requestGeneration = null,
  ) {
    const requestId = projectsRequestRef.current.id + 1;
    projectsRequestRef.current.controller?.abort();
    const controller = new AbortController();
    projectsRequestRef.current = { id: requestId, controller };

    const responsePolicy = () =>
      projectListResponsePolicy(
        projectsRequestRef.current.id,
        requestId,
        selectedPathRef.current,
        projectGenerationRef.current,
        requestPath,
        requestGeneration,
      );

    setLoading(true);
    try {
      const data = await api("/api/projects", {
        signal: controller.signal,
      });
      const policy = responsePolicy();
      if (!policy.applyData) return;

      setProjectRoot(data.project_root);
      setProjectRootMessage(data.message || "");
      setProjects(data.projects);
      if (!policy.applySelection) return;

      const currentPath = selectedPathRef.current;
      const selectableProjects = data.projects.filter((project) => project.available !== false);
      if (restorationPendingRef.current) {
        restorationPendingRef.current = false;
        const restored = stateForWorkspace(initialSessionStateRef.current, data.project_root);
        const restoredProject = restored
          ? selectableProjects.find((project) => project.path === restored.selectedProjectPath)
          : null;
        if (restored) {
          setMajorSectionsOpen({ ...OPEN_MAJOR_SECTIONS, ...restored.panels });
          setSelectedSection(
            PROJECT_REQUIRED_SECTIONS.has(restored.activeSection) && !restoredProject
              ? "workspace"
              : restored.activeSection,
          );
          if (restoredProject && restored.selectedScanId !== null) {
            pendingScanRestoreRef.current = {
              projectPath: restoredProject.path,
              scanId: restored.selectedScanId,
            };
          }
        }
        const initialPath = restoredProject?.path || selectableProjects[0]?.path || "";
        selectProject(initialPath, { restoring: true });
        setSessionStateReady(true);
        return;
      }

      const stillSelected = selectableProjects.some((project) => project.path === currentPath);
      if ((!currentPath || !stillSelected) && selectableProjects.length > 0) {
        selectProject(selectableProjects[0].path);
      }
      if (!stillSelected && selectableProjects.length === 0) {
        selectProject("");
      }
    } catch (error) {
      if (!isAbortError(error) && responsePolicy().applySelection) {
        setMessage(error.message);
      }
    } finally {
      if (projectsRequestRef.current.id === requestId) {
        setLoading(false);
      }
    }
  }

  async function createProject(event) {
    event.preventDefault();
    const workspaceGeneration = workspaceGenerationRef.current;
    try {
      const created = await api("/api/projects", {
        method: "POST",
        body: {
          project_name: createForm.project_name,
          description: createForm.description,
          project_type: createForm.project_type,
        },
      });
      if (workspaceGenerationRef.current !== workspaceGeneration) return;
      setMessage(`Created ${created.name}`);
      setCreateForm({ project_name: "", existing_path: "", description: "", project_type: "" });
      setCreateProjectOpen(false);
      await refreshProjects();
      if (workspaceGenerationRef.current === workspaceGeneration) {
        selectProject(created.path);
        setSelectedSection("workspace");
      }
    } catch (error) {
      if (workspaceGenerationRef.current === workspaceGeneration) setMessage(error.message);
    }
  }

  async function registerExistingProject(event) {
    event.preventDefault();
    const workspaceGeneration = workspaceGenerationRef.current;
    try {
      const registered = await api("/api/projects/register", {
        method: "POST",
        body: {
          project_path: createForm.existing_path,
          description: createForm.description,
          project_type: createForm.project_type,
        },
      });
      if (workspaceGenerationRef.current !== workspaceGeneration) return;
      setMessage(`Registered ${registered.name}`);
      setCreateForm({ project_name: "", existing_path: "", description: "", project_type: "" });
      setCreateProjectOpen(false);
      await refreshProjects();
      if (workspaceGenerationRef.current === workspaceGeneration) {
        selectProject(registered.path);
        setSelectedSection("workspace");
      }
    } catch (error) {
      if (workspaceGenerationRef.current === workspaceGeneration) setMessage(error.message);
    }
  }

  async function loadChangelog() {
    try {
      const data = await api("/api/changelog");
      setChangelog(data.entries || []);
    } catch (error) {
      setMessage(error.message);
    }
  }

  async function checkHealth() {
    setBackendHealth("checking");
    try {
      const data = await api("/api/health");
      setBackendHealth(data.status === "ok" ? "reachable" : "unreachable");
    } catch {
      setBackendHealth("unreachable");
    }
  }

  async function previewAgents(event) {
    event.preventDefault();
    const projectPath = selectedPathRef.current;
    const generation = projectGenerationRef.current;
    if (!projectPath) return;
    const requestId = beginScopedProjectRequest("agentPreview");
    try {
      const data = await api("/api/agents/preview", {
        method: "POST",
        body: { project_path: projectPath, ...agentForm },
      });
      if (!scopedProjectRequestIsCurrent("agentPreview", requestId, projectPath, generation)) return;
      setAgentPreview(data.content);
      setMessage("AGENTS.md preview generated.");
    } catch (error) {
      if (!isAbortError(error) && scopedProjectRequestIsCurrent("agentPreview", requestId, projectPath, generation)) {
        setMessage(error.message);
      }
    }
  }

  function updateAgentField(field, value) {
    beginScopedProjectRequest("agentPreview");
    setAgentForm({ ...agentForm, [field]: value });
    setAgentPreview("");
  }

  async function writeAgents() {
    const projectPath = selectedPathRef.current;
    const generation = projectGenerationRef.current;
    if (!projectPath) return;
    beginScopedProjectRequest("agentPreview");
    const requestId = beginScopedProjectRequest("agentWrite");
    try {
      const overwrite = agentsExists
        ? window.confirm("AGENTS.md already exists for this project. Overwrite it with the previewed content?")
        : false;

      if (agentsExists && !overwrite) {
        if (projectRequestIsCurrent(projectPath, generation)) {
          setMessage("Write canceled. Existing AGENTS.md was not changed.");
        }
        return;
      }

      const data = await api("/api/agents/write", {
        method: "POST",
        body: { project_path: projectPath, ...agentForm, overwrite },
      });
      if (!scopedProjectRequestIsCurrent("agentWrite", requestId, projectPath, generation)) {
        reloadSelectedProjectAfterStaleMutation(projectPath, generation);
        return;
      }
      beginScopedProjectRequest("agentsExists");
      if (data.confirmation_required) {
        setAgentsExists(true);
        setMessage(data.message);
        return;
      }
      setAgentPreview(data.content);
      setAgentsExists(true);
      setMessage(data.message || `Wrote ${data.path}`);
    } catch (error) {
      if (!isAbortError(error) && scopedProjectRequestIsCurrent("agentWrite", requestId, projectPath, generation)) {
        setMessage(error.message);
      }
    }
  }

  async function checkAgentsExists(path, generation, signal) {
    const requestId = beginScopedProjectRequest("agentsExists");
    try {
      const data = await api(`/api/agents/exists?project_path=${encodeURIComponent(path)}`, { signal });
      if (!scopedProjectRequestIsCurrent("agentsExists", requestId, path, generation)) return;
      setAgentsExists(Boolean(data.exists));
    } catch (error) {
      if (!isAbortError(error) && scopedProjectRequestIsCurrent("agentsExists", requestId, path, generation)) {
        setAgentsExists(false);
        setMessage(error.message);
      }
    }
  }

  async function runScan() {
    const projectPath = selectedPathRef.current;
    const generation = projectGenerationRef.current;
    const workspaceGeneration = workspaceGenerationRef.current;
    if (!projectPath || scanningRef.current) return;
    const requestId = beginScopedProjectRequest("scanMutation");
    scanningRef.current = true;
    setIsScanning(true);
    try {
      const data = await api("/api/scans", { method: "POST", body: { project_path: projectPath } });
      if (scopedProjectRequestIsCurrent("scanMutation", requestId, projectPath, generation)) {
        setScanResult(data);
        setSelectedScanId(null);
        setSelectedSection("reports");
        setMajorSectionOpen("scanReport", true);
        setMessage("Scan complete. Continue with the guided review.");
        await loadScanHistory(projectPath, generation);
        if (!projectRequestIsCurrent(projectPath, generation)) {
          reloadSelectedProjectAfterStaleMutation(projectPath, generation);
        }
      } else if (projectRequestIsCurrent(projectPath, generation)) {
        await loadScanHistory(projectPath, generation);
        if (!projectRequestIsCurrent(projectPath, generation)) {
          reloadSelectedProjectAfterStaleMutation(projectPath, generation);
        }
      } else {
        reloadSelectedProjectAfterStaleMutation(projectPath, generation);
      }
      if (projectRequestIsCurrent(projectPath, generation)) {
        await loadActivity(projectPath, generation);
      }
      if (workspaceGenerationRef.current === workspaceGeneration) {
        await refreshProjects(projectPath, generation);
      }
    } catch (error) {
      if (!isAbortError(error) && scopedProjectRequestIsCurrent("scanMutation", requestId, projectPath, generation)) {
        setMessage(error.message);
      }
    } finally {
      if (scopedProjectRequestIsCurrent("scanMutation", requestId, projectPath, generation)) {
        scanningRef.current = false;
        setIsScanning(false);
      }
    }
  }

  async function loadScanHistory(path, generation, signal) {
    const requestId = beginScopedProjectRequest("scanHistory");
    try {
      const data = await api(`/api/scans/history?project_path=${encodeURIComponent(path)}`, { signal });
      if (!scopedProjectRequestIsCurrent("scanHistory", requestId, path, generation)) return;
      setScanHistory(data.scans);
      setScanResult((current) => current ? (data.scans.find((scan) => scan.id === current.id) || current) : current);
      const pending = pendingScanRestoreRef.current;
      if (pending?.projectPath === path) {
        pendingScanRestoreRef.current = null;
        if (data.scans.some((scan) => scan.id === pending.scanId)) setSelectedScanId(pending.scanId);
      }
      return data.scans;
    } catch (error) {
      if (!isAbortError(error) && scopedProjectRequestIsCurrent("scanHistory", requestId, path, generation)) {
        if (pendingScanRestoreRef.current?.projectPath === path) pendingScanRestoreRef.current = null;
        setScanHistory([]);
        setMessage(error.message);
      }
    }
  }

  async function approveTrustedBaseline(scan, replace = false, note = "") {
    if (!scan?.id || !scan?.dependencyTrust?.trustedBaseline?.approval?.eligible) return;
    if (replace && !window.confirm("Replace the trusted dependency baseline? Project files and scan history will not be changed.")) return;
    await mutateTrustedBaseline("PUT", {
      scan_id: scan.id,
      fingerprint: scan.dependencyTrust.trustedBaseline.approval.fingerprint,
      note,
      replace,
    }, replace ? "Trusted dependency baseline replaced." : "Dependency snapshot approved as the trusted baseline.");
  }

  async function updateTrustedBaselineNote(note) {
    await mutateTrustedBaseline("PATCH", { note }, "Trusted baseline note updated.");
  }

  async function clearTrustedBaseline() {
    if (!window.confirm("Clear the trusted dependency baseline? Project files and scan history will not be changed.")) return;
    await mutateTrustedBaseline("DELETE", {}, "Trusted dependency baseline cleared.");
  }

  async function mutateTrustedBaseline(method, fields, success) {
    const projectPath = selectedPathRef.current;
    const generation = projectGenerationRef.current;
    if (!projectPath) return;
    const requestId = beginScopedProjectRequest("trustedBaselineMutation");
    trustedBaselineRequestRef.current.controller?.abort();
    const controller = new AbortController();
    trustedBaselineRequestRef.current = { id: requestId, controller };
    setTrustedBaselineMutation({ saving: true, error: "", success: "" });
    try {
      const data = await api("/api/trusted-dependency-baseline", {
        method,
        body: { project_path: projectPath, ...fields },
        signal: controller.signal,
      });
      if (!scopedProjectRequestIsCurrent("trustedBaselineMutation", requestId, projectPath, generation)) return;
      await loadScanHistory(projectPath, generation, controller.signal);
      if (!scopedProjectRequestIsCurrent("trustedBaselineMutation", requestId, projectPath, generation)) return;
      if (data.activity_recorded) {
        await loadActivity(projectPath, generation, controller.signal);
        if (!scopedProjectRequestIsCurrent("trustedBaselineMutation", requestId, projectPath, generation)) return;
      }
      setTrustedBaselineMutation({ saving: false, error: "", success });
    } catch (error) {
      if (!isAbortError(error) && scopedProjectRequestIsCurrent("trustedBaselineMutation", requestId, projectPath, generation)) {
        setTrustedBaselineMutation({ saving: false, error: error.message, success: "" });
      }
    }
  }

  async function loadNotes(path, generation, signal) {
    const requestId = beginScopedProjectRequest("notes");
    try {
      const data = await api(`/api/notes?project_path=${encodeURIComponent(path)}`, { signal });
      if (!scopedProjectRequestIsCurrent("notes", requestId, path, generation)) return;
      setNotes(data.notes);
    } catch (error) {
      if (!isAbortError(error) && scopedProjectRequestIsCurrent("notes", requestId, path, generation)) {
        setNotes([]);
        setMessage(error.message);
      }
    }
  }

  async function loadTrustProfile(path, generation, signal) {
    const requestId = beginScopedProjectRequest("trustProfile");
    try {
      const data = await api(`/api/trust-profile?project_path=${encodeURIComponent(path)}`, { signal });
      if (!scopedProjectRequestIsCurrent("trustProfile", requestId, path, generation)) return;
      setTrustProfile(normalizeProjectExpectations(data));
      setTrustProfileMessage("");
    } catch (error) {
      if (!isAbortError(error) && scopedProjectRequestIsCurrent("trustProfile", requestId, path, generation)) {
        setTrustProfile({ ...EMPTY_TRUST_PROFILE, project_path: path });
        setTrustProfileMessage(error.message);
      }
    }
  }

  async function loadActivity(path, generation, signal, offset = 0) {
    const requestId = beginScopedProjectRequest("activity");
    setActivity((current) => ({ ...current, loading: true, error: "" }));
    try {
      const data = await api(
        `/api/activity?project_path=${encodeURIComponent(path)}&limit=20&offset=${offset}`,
        { signal },
      );
      if (!scopedProjectRequestIsCurrent("activity", requestId, path, generation)) return;
      const page = normalizeActivityPage(data);
      setActivity((current) => ({
        events: offset > 0
          ? mergeActivityEvents(current.events, page.events)
          : page.events,
        hasMore: page.hasMore,
        nextOffset: page.nextOffset,
        loading: false,
        error: "",
      }));
    } catch (error) {
      if (!isAbortError(error) && scopedProjectRequestIsCurrent("activity", requestId, path, generation)) {
        setActivity((current) => ({ ...current, loading: false, error: error.message }));
      }
    }
  }

  async function loadOlderActivity() {
    const projectPath = selectedPathRef.current;
    const generation = projectGenerationRef.current;
    if (!projectPath || activity.loading || activity.nextOffset === null) return;
    await loadActivity(projectPath, generation, undefined, activity.nextOffset);
  }

  async function saveTrustProfile(profile, activityContext = null) {
    const projectPath = selectedPathRef.current;
    const generation = projectGenerationRef.current;
    if (!projectPath) return;
    beginScopedProjectRequest("trustProfile");
    const requestId = beginScopedProjectRequest("trustSave");
    try {
      const data = await api("/api/trust-profile", {
        method: "PUT",
        body: {
          ...profile,
          project_path: projectPath,
          activity_context: activityContext,
        },
      });
      if (!scopedProjectRequestIsCurrent("trustSave", requestId, projectPath, generation)) {
        reloadSelectedProjectAfterStaleMutation(projectPath, generation);
        return;
      }
      setTrustProfile(normalizeProjectExpectations(data));
      setTrustProfileMessage("Project Expectations saved.");
      if (data.activity_recorded) await loadActivity(projectPath, generation);
    } catch (error) {
      if (!isAbortError(error) && scopedProjectRequestIsCurrent("trustSave", requestId, projectPath, generation)) {
        setTrustProfileMessage(error.message);
      }
    }
  }

  async function addNote(event) {
    event.preventDefault();
    const projectPath = selectedPathRef.current;
    const generation = projectGenerationRef.current;
    const workspaceGeneration = workspaceGenerationRef.current;
    if (!projectPath || !noteBody.trim()) return;
    const requestId = beginScopedProjectRequest("noteMutation");
    try {
      await api("/api/notes", { method: "POST", body: { project_path: projectPath, body: noteBody } });
      if (projectRequestIsCurrent(projectPath, generation)) {
        if (scopedProjectRequestIsCurrent("noteMutation", requestId, projectPath, generation)) {
          setNoteBody("");
        }
        await loadNotes(projectPath, generation);
        if (!projectRequestIsCurrent(projectPath, generation)) {
          reloadSelectedProjectAfterStaleMutation(projectPath, generation);
        }
      } else {
        reloadSelectedProjectAfterStaleMutation(projectPath, generation);
      }

      if (workspaceGenerationRef.current === workspaceGeneration) {
        await refreshProjects(projectPath, generation);
      }
    } catch (error) {
      if (!isAbortError(error) && scopedProjectRequestIsCurrent("noteMutation", requestId, projectPath, generation)) {
        setMessage(error.message);
      }
    }
  }

  async function saveFindingReview(finding, status, note) {
    const fingerprint = finding?.fingerprint;
    const projectPath = selectedPathRef.current;
    const generation = projectGenerationRef.current;
    if (!fingerprint || !projectPath) return;
    const requestId = (findingReviewRequestsRef.current.get(fingerprint) || 0) + 1;
    findingReviewRequestsRef.current.set(fingerprint, requestId);
    setFindingReviewState((current) => ({ ...current, [fingerprint]: { saving: true, error: "", success: "" } }));
    try {
      const data = await api("/api/finding-reviews", {
        method: "PUT",
        body: {
          project_path: projectPath,
          fingerprint,
          status,
          note,
          scan_id: displayedScan?.id || null,
        },
      });
      if (!findingReviewRequestIsCurrent(fingerprint, requestId, projectPath, generation)) return;
      applyFindingReview(fingerprint, data.review);
      setFindingReviewState((current) => ({ ...current, [fingerprint]: { saving: false, error: "", success: "Review saved." } }));
      if (data.activity_recorded) await loadActivity(projectPath, generation);
    } catch (error) {
      if (!findingReviewRequestIsCurrent(fingerprint, requestId, projectPath, generation)) return;
      setFindingReviewState((current) => ({ ...current, [fingerprint]: { saving: false, error: error.message, success: "" } }));
    }
  }

  async function reopenFindingReview(finding) {
    const fingerprint = finding?.fingerprint;
    const projectPath = selectedPathRef.current;
    const generation = projectGenerationRef.current;
    if (!fingerprint || !projectPath) return;
    const requestId = (findingReviewRequestsRef.current.get(fingerprint) || 0) + 1;
    findingReviewRequestsRef.current.set(fingerprint, requestId);
    setFindingReviewState((current) => ({ ...current, [fingerprint]: { saving: true, error: "", success: "" } }));
    try {
      await api("/api/finding-reviews", {
        method: "DELETE",
        body: { project_path: projectPath, fingerprint },
      });
      if (!findingReviewRequestIsCurrent(fingerprint, requestId, projectPath, generation)) return;
      applyFindingReview(fingerprint, null);
      setFindingReviewState((current) => ({ ...current, [fingerprint]: { saving: false, error: "", success: "Finding reopened." } }));
    } catch (error) {
      if (!findingReviewRequestIsCurrent(fingerprint, requestId, projectPath, generation)) return;
      setFindingReviewState((current) => ({ ...current, [fingerprint]: { saving: false, error: error.message, success: "" } }));
    }
  }

  function findingReviewRequestIsCurrent(fingerprint, requestId, projectPath, generation) {
    return findingReviewRequestsRef.current.get(fingerprint) === requestId
      && projectRequestIsCurrent(projectPath, generation);
  }

  function applyFindingReview(fingerprint, review) {
    setScanResult((current) => applyFindingReviewToScan(current, fingerprint, review));
    setScanHistory((current) => current.map((scan) => applyFindingReviewToScan(scan, fingerprint, review)));
  }

  async function changeWorkspaceRoot(nextRoot) {
    const value = nextRoot.trim();
    if (!value) {
      setWorkspaceRootError("Workspace root is required.");
      return;
    }
    if (value === projectRoot) {
      setWorkspaceRootError("");
      return;
    }
    const confirmed = window.confirm(
      "Changing the workspace root clears the selected project and visible project details. Only registrations under the new root will be available. No project files or folders will be deleted. Continue?",
    );
    if (!confirmed) return;

    const requestId = workspaceRequestRef.current + 1;
    workspaceRequestRef.current = requestId;
    setWorkspaceRootChanging(true);
    setWorkspaceRootError("");
    try {
      const data = await api("/api/config/project-root", {
        method: "PUT",
        body: { project_root: value },
      });
      if (workspaceRequestRef.current !== requestId) return;
      clearSessionState();
      lastSessionWriteRef.current = "";
      initialSessionStateRef.current = null;
      pendingScanRestoreRef.current = null;
      workspaceGenerationRef.current += 1;
      unregisterRequestRef.current += 1;
      setUnregisteringPath("");
      projectsRequestRef.current.controller?.abort();
      selectProject("");
      setProjects([]);
      setProjectRoot(data.project_root);
      setProjectRootMessage("");
      await refreshProjects();
      if (workspaceRequestRef.current === requestId) {
        setMessage("Workspace root changed. No project files were modified.");
      }
    } catch (error) {
      if (workspaceRequestRef.current === requestId) setWorkspaceRootError(error.message);
    } finally {
      if (workspaceRequestRef.current === requestId) setWorkspaceRootChanging(false);
    }
  }

  async function saveProjectMetadata(project, metadata) {
    const projectPath = project.path;
    const generation = projectGenerationRef.current;
    const workspaceGeneration = workspaceGenerationRef.current;
    const requestId = beginScopedProjectRequest("metadataSave");
    setMetadataSaving(true);
    try {
      await api("/api/projects/metadata", {
        method: "PUT",
        body: { project_path: projectPath, ...metadata },
      });
      if (workspaceGenerationRef.current !== workspaceGeneration || !scopedProjectRequestIsCurrent("metadataSave", requestId, projectPath, generation)) return;
      await refreshProjects(projectPath, generation);
      if (scopedProjectRequestIsCurrent("metadataSave", requestId, projectPath, generation)) {
        setMessage("Project metadata saved.");
      }
    } catch (error) {
      if (scopedProjectRequestIsCurrent("metadataSave", requestId, projectPath, generation)) setMessage(error.message);
    } finally {
      if (scopedProjectRequestIsCurrent("metadataSave", requestId, projectPath, generation)) setMetadataSaving(false);
    }
  }

  async function unregisterProject(project) {
    const confirmed = window.confirm(
      `Unregister ${project.name} (${project.path}) from Glacial? Project files and folders will remain untouched.`,
    );
    if (!confirmed) return;
    const requestId = unregisterRequestRef.current + 1;
    const workspaceGeneration = workspaceGenerationRef.current;
    unregisterRequestRef.current = requestId;
    setUnregisteringPath(project.path);
    try {
      const data = await api("/api/projects", { method: "DELETE", body: { project_path: project.path } });
      if (unregisterRequestRef.current !== requestId || workspaceGenerationRef.current !== workspaceGeneration) return;
      if (selectedPathRef.current === project.path) {
        persistSessionSnapshot({ selectedProjectPath: "", selectedScanId: null });
        selectProject("");
      }
      await refreshProjects();
      if (unregisterRequestRef.current === requestId) setMessage(data.message);
    } catch (error) {
      if (unregisterRequestRef.current === requestId && workspaceGenerationRef.current === workspaceGeneration) setMessage(error.message);
    } finally {
      if (unregisterRequestRef.current === requestId && workspaceGenerationRef.current === workspaceGeneration) setUnregisteringPath("");
    }
  }

  function setMajorSectionOpen(section, open) {
    setMajorSectionsOpen((current) => (current[section] === open ? current : { ...current, [section]: open }));
  }

  function selectHistoricalScan(scanId) {
    pendingScanRestoreRef.current = null;
    setSelectedScanId(scanId);
  }

  function sessionSnapshot(overrides = {}) {
    return {
      workspaceRoot: projectRoot,
      selectedProjectPath: selectedPath,
      activeSection: selectedSection,
      selectedScanId,
      panels: majorSectionsOpen,
      ...overrides,
    };
  }

  function persistSessionSnapshot(overrides = {}) {
    const snapshot = sessionSnapshot(overrides);
    lastSessionWriteRef.current = serializeSessionState(snapshot) || "";
    writeSessionState(snapshot);
  }

  function resetSavedUiState() {
    pendingScanRestoreRef.current = null;
    restorationPendingRef.current = false;
    initialSessionStateRef.current = null;
    clearSessionState();
    lastSessionWriteRef.current = "";
    skipNextSessionWriteRef.current = true;
    setSelectedScanId(null);
    setSelectedSection("workspace");
    setMajorSectionsOpen({ ...OPEN_MAJOR_SECTIONS });
    const defaultProject = projects.find((project) => project.available !== false)?.path || "";
    selectProject(defaultProject, { restoring: true, force: true });
    setMessage("Saved UI state reset. Backend data and workspace configuration were not changed.");
  }

  function openReports() {
    setSelectedSection("reports");
    setMajorSectionOpen("scanReport", true);
  }

  function openActivityScan(scanId) {
    if (!scanHistory.some((scan) => scan.id === scanId)) return;
    setSelectedScanId(scanId);
    setSelectedSection("reports");
    setMajorSectionOpen("history", true);
  }

  function dismissSelectedGuidedReview() {
    if (!selectedPath) return;
    setDismissedGuidedReviews((current) => dismissGuidedReview(selectedPath, current));
  }

  function handleSidebarNav(event) {
    const link = event.target.closest("a");
    if (!link) return;
    const section = {
      "#workspace-overview": "workspace",
      "#projects": "projects",
      "#project-expectations": "trustProfiles",
      "#trust-profiles": "trustProfiles",
      "#activity": "activity",
      "#reports": "reports",
      "#changelog": "changelog",
      "#settings": "settings",
    }[link.hash];
    if (!section) return;
    event.preventDefault();
    setMessage((current) => current.startsWith("Saved UI state reset.") ? "" : current);
    setSelectedSection(section);
  }

  async function copyReportMarkdown() {
    if (!displayedReportMarkdown) return;
    if (!navigator.clipboard?.writeText) {
      setCopyStatus("Clipboard unavailable. Use Export instead.");
      return;
    }

    try {
      await navigator.clipboard.writeText(displayedReportMarkdown);
      setCopyStatus("Report Markdown copied.");
    } catch {
      setCopyStatus("Could not copy report Markdown.");
    }
  }

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand-block">
          <img className="brand-icon" src={glacialIcon} alt="" aria-hidden="true" />
          <div>
            <h1>Glacial</h1>
            <p>Local Project Scanner</p>
          </div>
        </div>

        <nav className="sidebar-nav" aria-label="Dashboard navigation" onClick={handleSidebarNav}>
          {SECTION_NAV.map((item) => (
            <a className={item.id === selectedSection ? "active" : ""} href={item.href} aria-current={item.id === selectedSection ? "page" : undefined} key={item.id}>
              <span aria-hidden="true">{item.icon}</span>
              {item.label}
            </a>
          ))}
        </nav>

        <div className="sidebar-section" id="projects">
          <h2>Local Projects</h2>
          {loading ? <p className="muted">Loading...</p> : null}
          <div className="project-list">
            {projects.map((project) => (
              <button
                key={project.path}
                className={`project-item ${project.path === selectedPath ? "selected" : ""}`}
                onClick={() => selectProject(project.path)}
                disabled={project.available === false}
                aria-pressed={project.path === selectedPath}
              >
                <span className="project-card-heading">
                  <span className="project-name" title={project.name}>{project.name}</span>
                </span>
                <span className="project-path" title={project.path}>{project.path}</span>
                <span className="project-card-meta">
                  <span className={`risk risk-${project.last_risk_level}`}>{projectFindingRiskLabel(project)}</span>
                  <span className="project-meta">{projectCoverageLabel(project)}</span>
                  <span className="project-meta">{project.notes_count} notes</span>
                  <span className="project-meta scan-time">{formatDate(project.last_scan_time)}</span>
                </span>
                {project.available === false ? <span className="project-availability">Unavailable: {project.availability}</span> : null}
              </button>
            ))}
            {!loading && projects.length === 0 ? <p className="muted">No project folders found.</p> : null}
          </div>
        </div>

        <div className="scanner-status">
          <span className="status-dot"></span>
          <div>
            <strong>{backendHealth === "reachable" ? "Backend reachable" : backendHealth === "checking" ? "Checking backend" : "Backend unavailable"}</strong>
            <p>{backendHealth !== "reachable"
              ? (backendHealth === "checking" ? "Scanner readiness pending" : "Scanner unavailable")
              : selectedProject
                ? (selectedProject.available === false ? "Project unavailable" : "Scanner ready for selected project")
                : "No project selected"}</p>
            {backendHealth === "unreachable" ? <button type="button" className="history-view-button" onClick={checkHealth}>Retry</button> : null}
          </div>
        </div>
      </aside>

      <section className="workspace">
        <header className="topbar" id="workspace-overview" ref={topbarRef}>
          <div>
            <h1>{selectedSectionInfo.label}</h1>
            <p>Local project dashboard for reviewing coding work before you run anything.</p>
          </div>
          {selectedSection !== "workspace" ? (
            <div className="topbar-actions">
              <button type="button" className="secondary-button" onClick={() => exportScanReport(displayedReportMarkdown)} disabled={!displayedReportMarkdown}>
                Export Report
              </button>
              <button type="button" className="secondary-button" onClick={copyReportMarkdown} disabled={!displayedReportMarkdown}>
                Copy Markdown
              </button>
              <button type="button" className="run-scan-button" onClick={runScan} disabled={!selectedPath || isScanning || selectedProject?.available === false}>
                {isScanning ? "Scanning..." : "Run Scan"}
              </button>
            </div>
          ) : null}
        </header>

        <div className="notice-stack" aria-live="polite" aria-atomic="false" style={{ "--toast-top": `${toastTop}px` }}>
          {message && <div className="notice">{message}</div>}
          {projectDetailsLoading && selectedProject ? <div className="notice subtle-notice">Loading project details...</div> : null}
          {copyStatus && <div className="notice subtle-notice">{copyStatus}</div>}
          {projectRootMessage && <div className="notice">{projectRootMessage}</div>}
        </div>
        <div className="workspace-root-line" title={selectedProject?.path || projectRoot}>
          Workspace: {selectedProject?.name || "No project selected"} <span>Path: {selectedProject?.path || projectRoot || "Loading workspace root..."}</span>
        </div>
        {selectedProject && (selectedProject.project_type || selectedProject.description) ? (
          <div className="workspace-root-line">
            {selectedProject.project_type ? <span>Type: {selectedProject.project_type}</span> : null}
            {selectedProject.description ? <span>Description: {selectedProject.description}</span> : null}
          </div>
        ) : null}

        <section className="content">
          {selectedSection === "workspace" && selectedProject && !projectDetailsLoading ? (
            <>
              {!dismissedGuidedReviews.includes(selectedPath) ? (
                <GuidedReviewChecklist
                  state={latestGuidedReview}
                  isScanning={isScanning}
                  onRunScan={runScan}
                  onOpenReports={openReports}
                  onDismiss={dismissSelectedGuidedReview}
                />
              ) : null}
              {displayedScan ? (
                <RiskSummaryHero
                  report={displayedReport}
                  result={displayedScan}
                  comparison={displayedComparison}
                  trustProfile={trustProfile}
                  isScanning={isScanning}
                  reportActionsDisabled={!displayedReportMarkdown}
                  runScanDisabled={!selectedPath || isScanning || selectedProject?.available === false}
                  onExport={() => exportScanReport(displayedReportMarkdown)}
                  onCopy={copyReportMarkdown}
                  onRunScan={runScan}
                />
              ) : (
                <FirstScanPrompt isScanning={isScanning} onRunScan={runScan} />
              )}
              <OverviewSecondarySummary projects={projects} report={displayedReport} result={displayedScan} />
              <section className="dashboard-grid">
                {displayedScan ? <FindingsOverview report={displayedReport} result={displayedScan} /> : null}
                {displayedScan ? <DependencyTrustPanel trust={displayedReport.dependencyTrust} findings={displayedReport.dependencyFindings} trustContext={displayedTrustContext} scan={displayedScan} viewMode={scanViewMode} compact trustedBaselineMutation={trustedBaselineMutation} onApproveTrustedBaseline={approveTrustedBaseline} onUpdateTrustedBaselineNote={updateTrustedBaselineNote} onClearTrustedBaseline={clearTrustedBaseline} onManageTrustedBaseline={() => { setSelectedSection("reports"); setMajorSectionOpen("scanReport", true); }} /> : null}
                <ProjectExpectationsSummary profile={trustProfile} onEdit={() => setSelectedSection("trustProfiles")} />
                <RecentActivity changelog={changelog} scans={scanHistory} />
              </section>
            </>
          ) : null}

          {selectedSection === "projects" ? (
            <ProjectsSection projects={projects} selectedPath={selectedPath} onSelectProject={selectProject} onNewProject={() => setCreateProjectOpen(true)} loading={loading} onSaveMetadata={saveProjectMetadata} metadataSaving={metadataSaving} onUnregister={unregisterProject} unregisteringPath={unregisteringPath} />
          ) : null}

          {selectedSection === "trustProfiles" && selectedProject && !projectDetailsLoading ? (
            <ProjectExpectationsPanel
              profile={trustProfile}
              report={latestProjectReport}
              scan={latestProjectScan}
              scans={scanHistory}
              message={trustProfileMessage}
              onSave={saveTrustProfile}
              onOpenReports={openReports}
            />
          ) : null}

          {selectedSection === "activity" && selectedProject && !projectDetailsLoading ? (
            <ActivityTimeline
              activity={activity}
              availableScanIds={new Set(scanHistory.map((scan) => scan.id))}
              onLoadOlder={loadOlderActivity}
              onOpenScan={openActivityScan}
            />
          ) : null}

          {selectedSection === "reports" && selectedProject && !projectDetailsLoading ? (
            <>
              <ScanReport
                result={displayedScan}
                report={displayedReport}
                completionState={displayedGuidedReview}
                comparison={displayedComparison}
                trustContext={displayedTrustContext}
                viewMode={scanViewMode}
                isScanning={isScanning}
                onRunScan={runScan}
                onReviewFinding={saveFindingReview}
                onReopenFinding={reopenFindingReview}
                findingReviewState={findingReviewState}
                trustedBaselineMutation={trustedBaselineMutation}
                onApproveTrustedBaseline={approveTrustedBaseline}
                onUpdateTrustedBaselineNote={updateTrustedBaselineNote}
                onClearTrustedBaseline={clearTrustedBaseline}
                open={majorSectionsOpen.scanReport}
                onOpenChange={(open) => setMajorSectionOpen("scanReport", open)}
              />
              <History scans={scanHistory} selectedScanId={selectedScanId} onSelectScan={selectHistoricalScan} open={majorSectionsOpen.history} onOpenChange={(open) => setMajorSectionOpen("history", open)} />
            </>
          ) : null}

          {selectedSection === "changelog" ? (
            <>
              <RecentActivity changelog={changelog} scans={scanHistory} />
              <Changelog entries={changelog} open={majorSectionsOpen.changelog} onOpenChange={(open) => setMajorSectionOpen("changelog", open)} />
            </>
          ) : null}

          {selectedSection === "settings" ? (
            <>
              <SettingsSection projectRoot={projectRoot} selectedProject={selectedProject} onChangeRoot={changeWorkspaceRoot} changing={workspaceRootChanging} error={workspaceRootError} onResetSavedState={resetSavedUiState} />
              {selectedProject && !projectDetailsLoading ? (
                <>
                  <AgentGenerator form={agentForm} updateField={updateAgentField} preview={agentPreview} exists={agentsExists} onPreview={previewAgents} onWrite={writeAgents} open={majorSectionsOpen.agents} onOpenChange={(open) => setMajorSectionOpen("agents", open)} />
                  <Notes notes={notes} noteBody={noteBody} setNoteBody={setNoteBody} onAdd={addNote} open={majorSectionsOpen.notes} onOpenChange={(open) => setMajorSectionOpen("notes", open)} />
                </>
              ) : null}
            </>
          ) : null}

          {!selectedProject && selectedSection !== "projects" ? (
            <div className="panel empty-state">
              <h2>No Project Selected</h2>
              <p>Create a project or select a folder under the configured workspace root.</p>
            </div>
          ) : null}
        </section>
      </section>
      {createProjectOpen ? (
        <CreateProjectModal
          form={createForm}
          setForm={setCreateForm}
          onSubmit={createProject}
          onRegister={registerExistingProject}
          onClose={() => setCreateProjectOpen(false)}
        />
      ) : null}
    </main>
  );
}

function GuidedReviewChecklist({ state, isScanning, onRunScan, onOpenReports, onDismiss }) {
  const nextAction = !state.hasScan
    ? { label: isScanning ? "Scanning..." : "Run first scan", onClick: onRunScan, disabled: isScanning }
    : state.workflowComplete
      ? { label: "View review summary", onClick: onOpenReports, disabled: false }
      : { label: "Continue review", onClick: onOpenReports, disabled: false };

  return (
    <section className={`guided-review guided-review-${state.status}`} aria-labelledby="guided-review-title">
      <div className="guided-review-heading">
        <div>
          <span className="guided-review-eyebrow">First-project review</span>
          <h2 id="guided-review-title">Guided review checklist</h2>
          <p>{state.completedStepCount} of {state.steps.length} steps complete. Completion records review work; it does not prove the project safe.</p>
        </div>
        <button type="button" className="tertiary-button guided-review-dismiss" onClick={onDismiss}>Dismiss</button>
      </div>
      <ol className="guided-review-steps">
        {state.steps.map((step) => (
          <li className={step.complete ? "complete" : "pending"} key={step.id}>
            <span className="guided-review-marker" aria-hidden="true">{step.complete ? "✓" : "·"}</span>
            <span>
              <strong>{step.label}</strong>
              <small>{step.detail}</small>
            </span>
          </li>
        ))}
      </ol>
      <div className="guided-review-actions">
        <button type="button" className="run-scan-button" onClick={nextAction.onClick} disabled={nextAction.disabled}>{nextAction.label}</button>
        {state.hasScan && !state.workflowComplete ? <span>{state.remaining[0]}</span> : null}
        {state.workflowComplete ? <span>Available review steps are complete for the latest scan.</span> : null}
      </div>
    </section>
  );
}

function FirstScanPrompt({ isScanning, onRunScan }) {
  return (
    <section className="panel first-scan-prompt" aria-labelledby="first-scan-title">
      <span className="guided-review-eyebrow">Next step</span>
      <h2 id="first-scan-title">Run this project’s first scan</h2>
      <p>Glacial will inspect supported local project metadata and text without executing project content. The scan establishes findings, coverage, and dependency context for review.</p>
      <div className="first-scan-actions">
        <button type="button" className="run-scan-button" onClick={onRunScan} disabled={isScanning}>{isScanning ? "Scanning..." : "Run first scan"}</button>
        <span>No safety or verification claim is made before or after the scan.</span>
      </div>
    </section>
  );
}

function RiskSummaryHero({ report, result, comparison, trustProfile, isScanning, reportActionsDisabled, runScanDisabled, onExport, onCopy, onRunScan }) {
  const hasScan = Boolean(result);
  const completeness = report.completeness;
  const reviewSummary = report.reviewSummary;
  const risk = result?.overall_risk || "none";
  const coverageUnknown = hasScan && !completeness.known;
  const reasons = hasScan ? buildRiskReasons(report, risk) : [];
  const reasonTone = hasScan ? overallRiskReasonTone(report, risk) : "neutral";
  const riskLabel = hasScan ? formatRiskLabel(risk) : "NOT SCANNED";
  const findingLabel = hasScan ? report.totalFindings : "—";
  const context = [
    { label: "Raw risk", value: riskLabel, detail: hasScan ? "Original scanner severity" : "Run the first scan", risk: hasScan ? risk : "none" },
    { label: "Highest unreviewed", value: hasScan ? formatRiskLabel(reviewSummary.highestUnreviewedSeverity) : "N/A", detail: "Highest unresolved severity", risk: hasScan ? reviewSummary.highestUnreviewedSeverity : "none" },
    { label: "Scan coverage", value: hasScan ? coverageLabel(completeness) : "NOT SCANNED", detail: hasScan ? coverageDetail(completeness) : "Coverage unavailable", risk: hasScan && !completeness.complete ? "medium" : "none" },
    { label: "Finding count", value: hasScan ? report.totalFindings : "N/A", detail: hasScan ? `${reviewSummary.unreviewedFindingCount} unresolved · ${reviewSummary.reviewedFindingCount} reviewed` : "No scan data" },
    { label: "Change since last scan", value: hasScan ? (comparison?.riskChange || "No previous scan") : "NOT SCANNED", detail: hasScan ? (comparison?.findingDelta || "Baseline not established") : "Run the first scan" },
    { label: "Risk tolerance", value: trustProfile.riskTolerance || "normal", detail: "Project review setting" },
  ];

  return (
    <section className={`panel overall-risk-panel risk-summary-hero${coverageUnknown ? " coverage-unknown" : ""}`} aria-labelledby="risk-summary-title">
      <div className="risk-summary-graphic">
        <span className="risk-summary-eyebrow">Current project risk</span>
        <div className={`risk-ring risk-ring-${hasScan ? (coverageUnknown ? "unknown" : risk) : "unknown"}`} aria-hidden="true">
          <strong>{riskLabel}</strong>
          <span>{findingLabel}</span>
          <small>{report.totalFindings === 1 ? "Finding" : "Findings"}</small>
        </div>
        <p className="risk-ring-caption">Risk level: <strong>{riskLabel}</strong> · {hasScan ? `${report.totalFindings} ${report.totalFindings === 1 ? "finding" : "findings"}` : "finding count unavailable"}</p>
      </div>

      <div className="risk-summary-content">
        <div className="risk-summary-heading">
          <span className="risk-summary-eyebrow">Risk summary</span>
          <h2 id="risk-summary-title">Current scanner result</h2>
          <p>{hasScan ? riskSummaryText(report, risk) : "Run the first scan to calculate risk and review project findings."}</p>
        </div>

        <dl className="risk-context-grid">
          {context.map((item) => (
            <div key={item.label}>
              <dt>{item.label}</dt>
              <dd className={item.risk ? `risk-text-${item.risk}` : undefined}>{item.value}</dd>
              <p>{item.detail}</p>
            </div>
          ))}
        </dl>

        {hasScan ? (
          <div className="risk-reasons">
            <ul>
              {reasons.slice(0, 4).map((reason) => (
                <li className={`risk-indicator risk-indicator-${reasonTone}`} key={reason}>
                  <span className="risk-indicator-symbol" aria-hidden="true">{riskIndicatorSymbol(reasonTone)}</span>
                  <span>{reason}</span>
                </li>
              ))}
              <li className="risk-indicator risk-indicator-neutral">
                <span className="risk-indicator-symbol" aria-hidden="true">{riskIndicatorSymbol("neutral")}</span>
                <span>Risk tolerance: {trustProfile.riskTolerance || "normal"}</span>
              </li>
            </ul>
          </div>
        ) : null}

        <div className="risk-summary-actions">
          <button type="button" className="run-scan-button" onClick={onRunScan} disabled={runScanDisabled}>
            {isScanning ? "Scanning..." : "Run Scan"}
          </button>
          <button type="button" className="secondary-button" onClick={onExport} disabled={reportActionsDisabled}>Export Report</button>
          <button type="button" className="secondary-button" onClick={onCopy} disabled={reportActionsDisabled}>Copy Markdown</button>
        </div>
      </div>
    </section>
  );
}

function OverviewSecondarySummary({ projects, report, result }) {
  const hasScan = Boolean(result);
  const reviewSummary = report.reviewSummary;
  const metrics = [
    ["Projects", projects.length],
    ["Last scan", formatDate(result?.scan_date)],
    ["Unresolved", hasScan ? reviewSummary.unreviewedFindingCount : "N/A"],
    ["Reviewed", hasScan ? reviewSummary.reviewedFindingCount : "N/A"],
    ["Reviewed files", hasScan ? report.reviewedFileCount : "N/A"],
    ["Ignored files", hasScan ? report.ignoredFileCount : "N/A"],
    ["Manifests", hasScan ? report.manifests.length : "N/A"],
    ["Lockfiles", hasScan ? report.lockfiles.length : "N/A"],
  ];

  return (
    <section className="overview-secondary-summary" aria-label="Workspace scan summary">
      {metrics.map(([label, value]) => (
        <div key={label}>
          <span>{label}</span>
          <strong>{value}</strong>
        </div>
      ))}
    </section>
  );
}

function CreateProjectModal({ form, setForm, onSubmit, onRegister, onClose }) {
  return (
    <div className="modal-backdrop" role="presentation">
      <section className="modal-panel" role="dialog" aria-modal="true" aria-labelledby="new-project-title">
        <div className="panel-heading">
          <div>
            <h2 id="new-project-title">Add Project</h2>
            <p className="muted">Register an existing folder or create a new folder inside the workspace root.</p>
          </div>
          <button type="button" className="tertiary-button modal-close" onClick={onClose}>Close</button>
        </div>
        <form onSubmit={onRegister} className="stack project-action-form">
          <h3>Add Existing Folder</h3>
          <input value={form.existing_path} onChange={(event) => setForm({ ...form, existing_path: event.target.value })} placeholder="Absolute folder path inside the workspace root" required />
          <input value={form.project_type} onChange={(event) => setForm({ ...form, project_type: event.target.value })} placeholder="Project type" />
          <textarea value={form.description} onChange={(event) => setForm({ ...form, description: event.target.value })} placeholder="Description" rows="2" />
          <button type="submit">Add Existing Folder</button>
        </form>
        <form onSubmit={onSubmit} className="stack project-action-form">
          <h3>Create New Folder</h3>
          <input value={form.project_name} onChange={(event) => setForm({ ...form, project_name: event.target.value })} placeholder="Project name" required />
          <input value={form.project_type} onChange={(event) => setForm({ ...form, project_type: event.target.value })} placeholder="Project type" />
          <textarea value={form.description} onChange={(event) => setForm({ ...form, description: event.target.value })} placeholder="Description" rows="3" />
          <button type="submit" className="secondary-button">Create New Folder</button>
        </form>
      </section>
    </div>
  );
}

function ProjectsSection({ projects, selectedPath, onSelectProject, onNewProject, loading, onSaveMetadata, metadataSaving, onUnregister, unregisteringPath }) {
  const selected = projects.find((project) => project.path === selectedPath) || null;
  const [draft, setDraft] = useState({ description: "", project_type: "" });

  useEffect(() => {
    setDraft({ description: selected?.description || "", project_type: selected?.project_type || "" });
  }, [selected?.path, selected?.description, selected?.project_type]);

  return (
    <section className="panel projects-section">
      <div className="panel-heading">
        <div>
          <h2>Projects</h2>
          <p className="muted">Registered project folders can be selected, scanned, and reviewed independently.</p>
        </div>
        <button type="button" className="new-project-button inline-action" onClick={onNewProject}>Add Project</button>
      </div>
      {loading ? <p className="muted">Loading projects...</p> : null}
      <div className="projects-table-scroll">
        <div className="projects-table" role="list" aria-label="Registered projects">
          {projects.map((project) => (
            <article className={`projects-table-row${selectedPath === project.path ? " selected" : ""}${project.available === false ? " unavailable" : ""}`} key={project.path} role="listitem">
              <button type="button" className="project-select-target" onClick={() => onSelectProject(project.path)} disabled={project.available === false} aria-pressed={selectedPath === project.path}>
                <span className="project-identity">
                  <span className="project-name-line">
                    <strong>{project.name}</strong>
                    {selectedPath === project.path ? <span className="selected-project-marker">Selected project</span> : null}
                  </span>
                  <span className="project-path" title={project.path}>{project.path}</span>
                  {project.project_type ? <span className="project-type">{project.project_type}</span> : null}
                  {project.available === false ? <span className="project-availability">Unavailable: {project.availability}</span> : null}
                </span>
                <span className="project-risk-cell">
                  <small>Scan status</small>
                  <span className={`risk risk-${project.last_risk_level}`}>{projectFindingRiskLabel(project)}</span>
                  <span>{projectCoverageLabel(project)}</span>
                </span>
                <span className="project-facts">
                  <span className="project-notes"><small>Notes</small><strong>{project.notes_count}</strong></span>
                  <span className="project-last-scan"><small>Last scan</small><strong>{formatDate(project.last_scan_time)}</strong></span>
                </span>
              </button>
              <div className="project-row-actions">
                <button type="button" className="history-view-button destructive-button" onClick={() => onUnregister(project)} disabled={Boolean(unregisteringPath)}>
                  {unregisteringPath === project.path ? "Unregistering..." : "Unregister"}
                </button>
              </div>
            </article>
          ))}
        </div>
      </div>
      {!loading && projects.length === 0 ? <p className="muted">No project folders found.</p> : null}
      {selected && selected.available !== false ? (
        <section className="project-metadata-editor" aria-labelledby="project-metadata-title">
          <div className="project-metadata-heading">
            <div>
              <h3 id="project-metadata-title">Edit project details</h3>
              <p><strong>{selected.name}</strong><span>{selected.path}</span></p>
            </div>
          </div>
          <form className="project-action-form project-metadata-form" onSubmit={(event) => { event.preventDefault(); onSaveMetadata(selected, draft); }}>
            <label>
              Project type
              <input value={draft.project_type} maxLength="120" onInput={(event) => setDraft({ ...draft, project_type: event.target.value })} placeholder="Optional" />
            </label>
            <label className="project-description-field">
              Description
              <textarea value={draft.description} maxLength="2000" onInput={(event) => setDraft({ ...draft, description: event.target.value })} placeholder="Optional project context" rows="2" />
            </label>
            <button type="submit" disabled={metadataSaving}>{metadataSaving ? "Saving..." : "Save Metadata"}</button>
          </form>
        </section>
      ) : null}
    </section>
  );
}

function ProjectExpectationsSummary({ profile, onEdit }) {
  const rows = [
    ["Package managers", profileList(profile, "trustedPackageManagers")],
    ["Dependency manifests", profileList(profile, "expectedManifestFiles")],
    ["Lockfiles", profileList(profile, "expectedLockfiles")],
    ["Lifecycle scripts", profileList(profile, "allowedLifecycleScripts")],
    ["Ecosystems", profileList(profile, "expectedEcosystems")],
    ["Reviewed paths", profileList(profile, "reviewedPaths")],
    ["Expected ignored paths", profileList(profile, "ignoredPaths")],
  ];
  const visibleRows = rows.filter(([, values]) => values.length > 0);
  const displayRows = visibleRows.length > 0 ? visibleRows : rows.slice(0, 4);

  return (
    <section className="panel overview-panel trust-profile-panel">
      <div className="panel-heading">
        <div>
          <h2>Project Expectations</h2>
          <p className="muted">Explicitly approved review context. Scan observations are never accepted automatically.</p>
        </div>
        <button type="button" className="secondary-button compact-action" onClick={onEdit}>Review Expectations</button>
      </div>
      <div className="expectations-grid">
        {displayRows.map(([label, values]) => (
          <div className="expectation-row" key={label}>
            <strong>{label}</strong>
            <span className={values?.length ? "" : "empty-value"}>{values?.length ? values.join(", ") : "Not set"}</span>
          </div>
        ))}
      </div>
    </section>
  );
}

function SettingsSection({ projectRoot, selectedProject, onChangeRoot, changing, error, onResetSavedState }) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(projectRoot);

  useEffect(() => {
    setDraft(projectRoot);
    setEditing(false);
  }, [projectRoot]);

  return (
    <section className="panel settings-section">
      <div className="panel-heading">
        <div>
          <h2>Settings</h2>
          <p className="muted">Change the local workspace root without moving or deleting project folders.</p>
        </div>
      </div>
      <div className="settings-list">
        <div>
          <strong>Workspace root</strong>
          <span>{projectRoot || "Loading workspace root..."}</span>
          {!editing ? <button type="button" className="secondary-button compact-action" onClick={() => setEditing(true)}>Change</button> : null}
        </div>
        <div>
          <strong>Selected project</strong>
          <span>{selectedProject?.path || "No project selected"}</span>
        </div>
        <div>
          <strong>Runtime model</strong>
          <span>Local scanner, local SQLite storage, no cloud sync.</span>
        </div>
        <div>
          <strong>Product</strong>
          <span>Glacial by Icefields · icefields.dev</span>
        </div>
      </div>
      {editing ? (
        <form className="stack project-action-form" onSubmit={(event) => { event.preventDefault(); onChangeRoot(draft); }}>
          <label>
            New absolute workspace root
            <input value={draft} onInput={(event) => setDraft(event.target.value)} disabled={changing} required />
          </label>
          <p className="muted">Changing roots clears visible project details and shows only registrations valid under the new root. No files or folders are deleted.</p>
          {error ? <p className="notice">{error}</p> : null}
          <div className="actions">
            <button type="submit" disabled={changing}>{changing ? "Changing..." : "Apply Workspace Root"}</button>
            <button type="button" className="secondary-button" onClick={() => { setEditing(false); setDraft(projectRoot); }} disabled={changing}>Cancel</button>
          </div>
        </form>
      ) : null}
      <div className="settings-reset-state">
        <strong>Saved UI state</strong>
        <p className="muted">Reset the saved project selection, active section, historical scan, and panel layout. Backend projects, scans, notes, Project Expectations, and workspace configuration are not changed.</p>
        <button type="button" className="secondary-button" onClick={onResetSavedState}>Reset saved UI state</button>
      </div>
    </section>
  );
}

function FindingsOverview({ report, result }) {
  if (!result) {
    return (
      <section className="panel overview-panel findings-overview">
        <div className="panel-heading">
          <div>
            <h2>Scan Report / Findings Overview</h2>
            <p className="muted">No scan results are available for this project yet.</p>
          </div>
        </div>
        <p className="muted">Run the first scan to review manifests, lockfiles, scripts, and other findings.</p>
      </section>
    );
  }

  const rows = scanCategoryRows(report);
  return (
    <section className="panel overview-panel findings-overview">
      <div className="panel-heading">
        <div>
          <h2>Scan Report / Findings Overview</h2>
          <p className="muted">Results from the displayed scan across all categories.</p>
        </div>
      </div>
      <div className="category-table">
        <div className="category-header">
          <span>Category</span>
          <span>Findings</span>
          <span>Status</span>
        </div>
        {rows.map((row) => {
          const status = categoryStatus(row, report.completeness);
          return (
            <div className="category-row" key={row.label}>
              <span>{row.label}</span>
              <strong>{row.count}</strong>
              <span className={status.className}>{status.label}</span>
            </div>
          );
        })}
      </div>
      {!report.completeness.known ? <p className="notice">{unknownCoverageMessage(report)} Run a new scan to verify current coverage.</p> : null}
      {report.totalFindings === 0 && report.completeness.known && report.completeness.complete ? <p className="good overview-good">Complete scan with no findings detected. Review generated code before running it.</p> : null}
    </section>
  );
}

function RecentActivity({ changelog, scans }) {
  return (
    <section className="panel overview-panel recent-activity" id="changelog">
      <div className="panel-heading">
        <div>
          <h2>Changelog / Recent Activity</h2>
          <p className="muted">What changed in Glacial and recent local scan activity.</p>
        </div>
      </div>
      <div className="activity-list">
        {changelog.slice(0, 4).map((entry) => (
          <div className="activity-row" key={entry.version}>
            <span>{entry.version}</span>
            <strong>{entry.title}</strong>
          </div>
        ))}
        {scans.slice(0, 3).map((scan) => (
          <div className="activity-row" key={`scan-${scan.id}`}>
            <span>{formatRiskLabel(scan.overall_risk)}</span>
            <strong>{scanActivityLabel(scan)} {formatDate(scan.scan_date)}</strong>
          </div>
        ))}
      </div>
    </section>
  );
}

function ActivityTimeline({ activity, availableScanIds, onLoadOlder, onOpenScan }) {
  const groups = groupActivityByDate(activity.events);
  return (
    <section className="panel activity-timeline" id="activity" aria-labelledby="activity-title">
      <div className="panel-heading">
        <div>
          <h2 id="activity-title">Project Activity</h2>
          <p className="muted">Meaningful persisted project history. Activity is read-only.</p>
        </div>
      </div>
      {groups.map((group) => (
        <section className="activity-date-group" key={group.label}>
          <h3>{group.label}</h3>
          <div className="project-activity-list">
            {group.events.map((event) => (
              <article className="project-activity-entry" key={event.eventId}>
                <time dateTime={event.timestamp || undefined}>{activityTimeLabel(event.timestamp)}</time>
                <div>
                  <div className="project-activity-heading">
                    <strong>{activityTitle(event)}</strong>
                    {event.relatedScanId ? (
                      availableScanIds.has(event.relatedScanId) ? (
                        <button
                          type="button"
                          className="history-view-button"
                          onClick={() => onOpenScan(event.relatedScanId)}
                        >
                          Scan #{event.relatedScanId}
                        </button>
                      ) : (
                        <span>Scan #{event.relatedScanId}</span>
                      )
                    ) : null}
                  </div>
                  <p>{activityDetail(event)}</p>
                </div>
              </article>
            ))}
          </div>
        </section>
      ))}
      {activity.events.length === 0 && !activity.loading && !activity.error ? (
        <p className="muted">No recorded project activity yet.</p>
      ) : null}
      {activity.error ? <p className="notice">{activity.error}</p> : null}
      {activity.hasMore ? (
        <button
          type="button"
          className="secondary-button compact-action activity-load-older"
          onClick={onLoadOlder}
          disabled={activity.loading}
        >
          {activity.loading ? "Loading..." : "Load older activity"}
        </button>
      ) : activity.loading && activity.events.length === 0 ? <p className="muted">Loading activity...</p> : null}
    </section>
  );
}

function Changelog({ entries, open, onOpenChange }) {
  return (
    <details className="panel compact section-toggle" open={open} onToggle={(event) => onOpenChange(event.currentTarget.open)}>
      <summary className="section-summary">
        <span className="section-caret" aria-hidden="true"></span>
        <h2>Changelog</h2>
      </summary>
      <div className="section-body changelog-list">
          {entries.map((entry) => (
            <details className="changelog-entry" key={entry.version}>
              <summary className="changelog-heading">
                <span className="changelog-caret" aria-hidden="true"></span>
                <span className="version">{entry.version}</span>
                <strong>{entry.title}</strong>
              </summary>
              <ul>
                {entry.changes.map((change) => (
                  <li key={change}>{change}</li>
                ))}
              </ul>
            </details>
          ))}
          {entries.length === 0 ? <p className="muted">No changelog entries loaded.</p> : null}
      </div>
    </details>
  );
}

function ScanReport({ result, report, completionState, comparison, trustContext, viewMode, isScanning, onRunScan, onReviewFinding, onReopenFinding, findingReviewState, trustedBaselineMutation, onApproveTrustedBaseline, onUpdateTrustedBaselineNote, onClearTrustedBaseline, open, onOpenChange }) {
  return (
    <details className={`panel section-toggle${completionState.allFindingsReviewed ? " reviewed-findings" : ""}`} id="reports" open={open} onToggle={(event) => onOpenChange(event.currentTarget.open)}>
      <summary className="section-summary">
        <span className="section-caret" aria-hidden="true"></span>
        <div>
          <h2>Scan Report</h2>
          <p className="muted">Findings are review prompts, not proof of a problem.</p>
        </div>
        {result ? <ScanHeaderStatus result={result} completeness={report.completeness} /> : null}
      </summary>
      <div className="section-body">
      {!result ? <ReportFirstScanPrompt isScanning={isScanning} onRunScan={onRunScan} /> : null}
      {result ? (
        <>
          <ReviewCompletionSummary state={completionState} viewMode={viewMode} />
          <FindingWorkbench
            findings={result.findings}
            scanIdentity={result.id ?? result.scan_date}
            onReviewFinding={onReviewFinding}
            onReopenFinding={onReopenFinding}
            findingReviewState={findingReviewState}
          />
          <DependencyTrustPanel trust={report.dependencyTrust} findings={report.dependencyFindings} trustContext={trustContext} scan={result} viewMode={viewMode} attention={completionState.dependency.requiresAction} onReviewFinding={onReviewFinding} onReopenFinding={onReopenFinding} findingReviewState={findingReviewState} trustedBaselineMutation={trustedBaselineMutation} onApproveTrustedBaseline={onApproveTrustedBaseline} onUpdateTrustedBaselineNote={onUpdateTrustedBaselineNote} onClearTrustedBaseline={onClearTrustedBaseline} />
          <ScanCompletenessSummary completeness={report.completeness} viewMode={viewMode} isScanning={isScanning} onRunScan={onRunScan} />
          <div className="scan-view-label">
            {viewMode === "history" ? `Viewing history scan from ${formatDate(result.scan_date)}` : `Viewing latest scan from ${formatDate(result.scan_date)}`}
          </div>
          <details className="report-supporting-details" open={!completionState.allFindingsReviewed}>
            <summary>Scanner context and raw metrics</summary>
            <ScanSummary report={report} risk={result.overall_risk} />
            <RiskExplanation report={report} risk={result.overall_risk} />
          </details>
          <ScanComparison comparison={comparison} />
          <TrustProfileContext context={trustContext} />
          <div className="scan-detail-toggles">
            <PathDetails title="Reviewed files" items={report.reviewedFiles} recordedCount={report.reviewedFileCount} emptyText="No reviewed files recorded for this scan." guidance={SCAN_GUIDANCE.reviewedFiles} />
            <PathDetails title="Ignored files" items={report.ignoredFiles} recordedCount={report.ignoredFileCount} emptyText="No files ignored by .glacialignore." guidance={SCAN_GUIDANCE.ignoredFiles} />
          </div>
        </>
      ) : null}
      {result && report.totalFindings === 0 && report.completeness.known && report.completeness.complete ? <p className="good">Complete scan with no scanner findings. Still review generated code before running it.</p> : null}
      {result ? (
        <details className="category-detail-views">
          <summary>Category detail views</summary>
          <div className="scan-section-grid">
            <PathSection title="Manifests" items={report.manifests} emptyText="No manifests recorded for this scan." reviewKind="manifest" guidance={SCAN_GUIDANCE.manifests} />
            <FindingPathSection title="Lockfiles" items={report.lockfiles} findings={report.lockfileFindings} emptyText="No lockfiles recorded for this scan." guidance={SCAN_GUIDANCE.lockfiles} onReviewFinding={onReviewFinding} onReopenFinding={onReopenFinding} findingReviewState={findingReviewState} />
            <LifecycleSection items={report.lifecycleScripts} findings={report.lifecycleFindings} onReviewFinding={onReviewFinding} onReopenFinding={onReopenFinding} findingReviewState={findingReviewState} />
            <FindingSection title="Secret Findings" findings={report.secretFindings} emptyText="No secret-looking paths recorded for this scan." guidance={SCAN_GUIDANCE.secretFiles} onReviewFinding={onReviewFinding} onReopenFinding={onReopenFinding} findingReviewState={findingReviewState} />
            <FindingSection title="Executable Files" findings={report.executableFindings} emptyText="No executable files recorded for this scan." onReviewFinding={onReviewFinding} onReopenFinding={onReopenFinding} findingReviewState={findingReviewState} />
            <MetadataSection zone={report.zone} findings={report.metadataFindings} onReviewFinding={onReviewFinding} onReopenFinding={onReopenFinding} findingReviewState={findingReviewState} />
          </div>
        </details>
      ) : null}
      {result ? <p className="review-note">Review high severity items first, then lifecycle scripts and files that launch processes or fetch remote content.</p> : null}
      </div>
    </details>
  );
}

function ReportFirstScanPrompt({ isScanning, onRunScan }) {
  return (
    <section className="report-first-scan">
      <span className="guided-review-eyebrow">Review not started</span>
      <h3>Run the first scan to begin review</h3>
      <p>Findings, scan coverage, and dependency context will appear here. Glacial does not execute project content during the scan.</p>
      <button type="button" className="run-scan-button" onClick={onRunScan} disabled={isScanning}>{isScanning ? "Scanning..." : "Run first scan"}</button>
    </section>
  );
}

function ReviewCompletionSummary({ state, viewMode }) {
  return (
    <section className={`review-completion review-completion-${state.status}`} aria-labelledby="review-completion-title">
      <div className="review-completion-heading">
        <div>
          <span className="guided-review-eyebrow">{viewMode === "history" ? "Historical scan review" : "Current scan review"}</span>
          <h3 id="review-completion-title">{state.title}</h3>
        </div>
        <span className={`review-completion-status status-${state.status}`}>{state.workflowComplete ? "Available workflow complete" : "Action remains"}</span>
      </div>
      <p>{state.summary}</p>
      {state.remaining.length ? (
        <ul className="review-completion-remaining">
          {state.remaining.map((item) => <li key={item}>{item}</li>)}
        </ul>
      ) : null}
      <div className={`review-completion-dependency dependency-${state.dependency.status}`}>
        <strong>Dependency review</strong>
        <span>{state.dependency.label}</span>
        <small>{state.dependency.detail}</small>
      </div>
      {viewMode === "history" ? <p className="review-completion-history">This summary describes the selected historical scan and does not change its evidence.</p> : null}
      <p className="review-completion-disclaimer">Completing this workflow records human review and available scan coverage. It does not prove that the project is safe, secure, or fully verified.</p>
    </section>
  );
}

function RiskExplanation({ report, risk }) {
  const reasons = buildRiskReasons(report, risk || "none");

  return (
    <section className="risk-explanation">
      <h3>Why this risk?</h3>
      <ul>
        {reasons.map((reason) => (
          <li key={reason}>{reason}</li>
        ))}
      </ul>
    </section>
  );
}

function ScanSummary({ report, risk }) {
  return (
    <div className="scan-summary">
      <div>
        <span className="summary-label">Raw risk</span>
        <strong className={`risk risk-${risk || "none"}`}>{risk === "none" ? "No recorded risk" : risk}</strong>
      </div>
      <div>
        <span className="summary-label">Unreviewed risk</span>
        <strong className={`risk risk-${report.reviewSummary.highestUnreviewedSeverity}`}>{report.reviewSummary.highestUnreviewedSeverity}</strong>
      </div>
      <div>
        <span className="summary-label">Findings</span>
        <strong>{report.totalFindings}</strong>
      </div>
      <div>
        <span className="summary-label">Unresolved / reviewed</span>
        <strong>{report.reviewSummary.unreviewedFindingCount} / {report.reviewSummary.reviewedFindingCount}</strong>
      </div>
      <div>
        <span className="summary-label">Reviewed files</span>
        <strong>{report.reviewedFileCount}</strong>
      </div>
      <div>
        <span className="summary-label">Ignored</span>
        <strong>{report.ignoredFileCount}</strong>
      </div>
    </div>
  );
}

function ScanHeaderStatus({ result, completeness }) {
  const findingCount = result.findingCount ?? result.findings?.length ?? 0;
  const risk = result.overall_risk || "none";
  return (
    <div className="scan-header-status">
      <span className={`scan-header-finding-count${completeness.known && completeness.complete && findingCount === 0 ? " verified" : ""}`}>
        {findingCountLabel(findingCount)}
      </span>
      <span className={`scan-header-coverage ${coverageState(completeness)}`}>{coverageHeaderLabel(completeness)}</span>
      {risk !== "none" ? <span className={`risk risk-${risk}`}>Risk: {risk}</span> : null}
    </div>
  );
}

function ScanCompletenessSummary({ completeness, viewMode, isScanning, onRunScan }) {
  const needsRescan = !completeness.known || !completeness.complete;
  const completenessState = !completeness.known ? "unknown" : completeness.complete ? "complete" : "incomplete";
  return (
    <section className={`scan-completeness ${completenessState}`}>
      <h3>{coverageLabel(completeness)}</h3>
      {!completeness.known ? <p>Completeness metadata is unavailable for this older scan. Do not assume full coverage. Run a new scan to verify current coverage.</p> : (
        <div className="scan-completeness-counts">
          <span>Traversal failures: {completeness.traversalFailureCount}</span>
          <span>File inspection failures: {completeness.fileInspectionFailureCount}</span>
          <span>Oversized files: {completeness.oversizedFileCount}</span>
          <span>Unsafe paths skipped: {completeness.unsafePathCount}</span>
          <span>Dependency analysis failures: {completeness.dependencyAnalysisFailureCount}</span>
          <span>Repository policy exclusions: {completeness.policyExcludedFileCount}</span>
          <span>Scanner resource budgets exceeded: {completeness.resourceBudgetExceededCount}</span>
          <span>Total issues: {completeness.issueCount}</span>
        </div>
      )}
      {needsRescan ? (
        <div className="scan-completeness-action">
          {viewMode === "history" ? <p>This creates a new current scan and does not modify the historical scan being viewed.</p> : null}
          <button type="button" className="run-scan-button contextual-scan-button" onClick={onRunScan} disabled={isScanning}>
            {isScanning ? "Scanning..." : "Run Current Scan"}
          </button>
        </div>
      ) : null}
    </section>
  );
}

function DependencyTrustPanel({ trust, findings, trustContext, scan, viewMode = "latest", compact = false, attention = false, onReviewFinding, onReopenFinding, findingReviewState = {}, trustedBaselineMutation = {}, onApproveTrustedBaseline, onUpdateTrustedBaselineNote, onClearTrustedBaseline, onManageTrustedBaseline }) {
  const directEntries = trust.entries.filter((entry) => entry.direct);
  const visibleFindings = findings.slice(0, 50);
  const noSupportedMetadata = dependencyTrustHasNoSupportedMetadata(trust);
  const expectedManagers = trustContext?.packageManagers || [];
  const managerContext = trust.packageManagers.map((manager) => ({
    manager,
    expected: expectedManagers.some((expected) => String(expected).toLowerCase() === manager.toLowerCase()),
  }));
  return (
    <section className={`dependency-trust dependency-status-${trust.status}${compact ? " dependency-trust-overview" : ""}${attention ? " dependency-review-attention" : ""}`}>
      <div className="panel-heading">
        <div>
          <h3>Dependency Trust</h3>
          <p className="muted">Offline heuristic checks of supported local manifest and lockfile structures.</p>
        </div>
        <span className="dependency-status">{dependencyStatusLabel(trust)}</span>
      </div>
      <p className="muted dependency-state-description">{dependencyStatusDescription(trust)}</p>
      <TrustedDependencyBaselinePanel baseline={trust.trustedBaseline} scan={scan} viewMode={viewMode} compact={compact} mutation={trustedBaselineMutation} onApprove={onApproveTrustedBaseline} onUpdateNote={onUpdateTrustedBaselineNote} onClear={onClearTrustedBaseline} onManage={onManageTrustedBaseline} />
      {compact ? (
        trust.available && !noSupportedMetadata ? (
          <div className="dependency-overview-counts">
            <span>Manifests <strong>{trust.manifests.length}</strong></span>
            <span>Lockfiles <strong>{trust.lockfiles.length}</strong></span>
            <span>Direct dependencies <strong>{trust.directDependencyCount}</strong></span>
            <span>Dependency findings <strong>{findings.length}</strong></span>
          </div>
        ) : null
      ) : !trust.available || noSupportedMetadata ? (
        <p className="review-note">Offline-only: no dependency graph, package reputation, installed dependency code, or registry intelligence was analyzed.</p>
      ) : (
        <>
          <div className="dependency-metrics">
            <div><strong>{trust.directDependencyCount}</strong><span>Direct</span></div>
            <div><strong>{trust.lockedDependencyCount}</strong><span>Locked</span></div>
            <div><strong>{trust.integrityCoverage.present}/{trust.integrityCoverage.total}</strong><span>Integrity</span></div>
            <div><strong>{trust.unusualSourceCount}</strong><span>Unusual sources</span></div>
            <div><strong>{trust.installScriptIndicatorCount}</strong><span>Install indicators</span></div>
            <div><strong>{trust.consistencyIssueCount}</strong><span>Consistency issues</span></div>
          </div>
          <p className="dependency-ecosystems">
            Ecosystems: {trust.ecosystems.length ? trust.ecosystems.join(", ") : "None detected"}. Manifests detected: {trust.manifests.length}. Lockfiles detected: {trust.lockfiles.length}.
          </p>
          {trust.status === "complete" && findings.length === 0 ? <p className="good">Supported offline checks completed with no dependency findings. This does not provide full dependency resolution, registry reputation, or malware intelligence.</p> : null}
          {trust.limitations.length ? (
            <details className="dependency-details" open>
              <summary>Analysis limitations ({trust.limitations.length})</summary>
              <ul>{trust.limitations.map((item, index) => <li key={`${item.path}-${item.reason}-${index}`}>{item.path ? <code>{item.path}</code> : null} {item.explanation || item.reason}</li>)}</ul>
            </details>
          ) : null}
          {managerContext.length ? <p className="muted">Package managers: {managerContext.map((item) => `${item.manager}${expectedManagers.length ? (item.expected ? " (user approved)" : " (not in Project Expectations)") : ""}`).join(", ")}.</p> : null}
          <details className="dependency-details">
            <summary>Direct dependencies ({trust.directDependencyCount})</summary>
            <div className="dependency-entry-list">
              {directEntries.map((entry) => (
                <div className="dependency-entry" key={`${entry.ecosystem}-${entry.name}-${entry.group}`}>
                  <strong>{entry.name}</strong>
                  <span>{entry.group}</span>
                  <code>{entry.requestedSpecification || "No requested specification"}</code>
                  <span>Locked: {entry.lockedVersion || "Not recorded"}</span>
                  <span>Source: {entry.sourceType}{entry.sourceIdentifier ? ` (${entry.sourceIdentifier})` : ""}</span>
                  <span>Integrity: {entry.integrityPresent ? "Recorded" : "Not recorded"}</span>
                </div>
              ))}
              {!directEntries.length ? <p className="muted">No direct dependencies recorded.</p> : null}
            </div>
            {trust.hiddenEntryCount ? <p className="muted">{trust.hiddenEntryCount} additional normalized entries are not rendered.</p> : null}
          </details>
          <details className="dependency-details">
            <summary>Changes since previous scan ({trust.comparison.changeCount})</summary>
            {trust.comparison.baselineStatus !== "available" ? <p className="muted">{trust.comparison.explanation || "No compatible dependency baseline is available."}</p> : (
              trust.comparison.changeCount === 0 ? <p className="muted">No dependency changes recorded.</p> : <ul>
                {trust.comparison.changes.map((change, index) => <li key={`${change.changeType}-${change.name}-${index}`}><strong>{change.changeType}</strong>: {change.name || change.currentValue || "dependency analysis"}{change.lockedVersion ? ` ${change.lockedVersion}` : ""}{change.previousValue ? ` (previously ${change.previousValue})` : ""}</li>)}
                {dependencyFileChanges(trust.comparison.fileChanges).map((change) => <li key={`${change.type}-${change.path}`}><strong>{change.type}</strong>: <code>{change.path}</code></li>)}
              </ul>
            )}
            {trust.comparison.hiddenChangeCount ? <p className="muted">{trust.comparison.hiddenChangeCount} additional changes are not rendered.</p> : null}
          </details>
          <details className="dependency-details">
            <summary>Dependency findings ({findings.length})</summary>
            {visibleFindings.map((finding, index) => <FindingItem finding={finding} key={findingKey(finding, index)} onReviewFinding={onReviewFinding} onReopenFinding={onReopenFinding} requestState={findingReviewState[finding.fingerprint]} />)}
            {!findings.length ? <p className="muted">No dependency findings recorded.</p> : null}
            {findings.length > visibleFindings.length ? <p className="muted">{findings.length - visibleFindings.length} additional dependency findings are summarized in the counts.</p> : null}
          </details>
          <p className="review-note">Offline-only: Glacial does not contact registries, score package reputation, install dependencies, inspect installed package code, or execute project code.</p>
        </>
      )}
    </section>
  );
}

function TrustedDependencyBaselinePanel({ baseline, scan, viewMode, compact, mutation, onApprove, onUpdateNote, onClear, onManage }) {
  const [editingNote, setEditingNote] = useState(false);
  const [note, setNote] = useState(baseline.note || "");
  const comparison = baseline.comparison;
  const approvalEligible = viewMode === "latest" && baseline.approval.eligible;
  const canUseFullActions = !compact && onApprove && onUpdateNote && onClear;
  const historicalReason = "Historical scans cannot replace the active baseline. View the latest eligible scan to approve a snapshot.";
  const unavailableReason = viewMode === "history"
    ? baseline.approval.eligible || !baseline.approval.reason
      ? historicalReason
      : `${baseline.approval.reason} ${historicalReason}`
    : baseline.approval.reason || "This scan is not eligible.";
  const summary = baseline.configured
    ? comparison.explanation || "The active trusted baseline could not be compared with this scan."
    : approvalEligible
      ? "Approve this dependency snapshot to detect future drift."
      : `Approval unavailable: ${unavailableReason}`;

  useEffect(() => {
    setNote(baseline.note || "");
    setEditingNote(false);
  }, [scan?.project_path, scan?.id, baseline.fingerprint, baseline.note, baseline.configured]);

  return (
    <section className={`trusted-baseline trusted-baseline-${comparison.status}`}>
      <div className="trusted-baseline-heading">
        <div>
          <h4>Trusted Dependency Baseline</h4>
          <p>{baseline.configured ? "Explicit project-scoped dependency snapshot." : "Project-scoped dependency drift reference."}</p>
        </div>
        <span className={`dependency-status trusted-baseline-status status-${comparison.status}`}>{trustedBaselineComparisonLabel(comparison.status)}</span>
      </div>
      <p className="muted trusted-baseline-summary">{summary}</p>
      {baseline.configured && baseline.valid ? (
        <div className="trusted-baseline-metadata">
          <span>Approved {formatDate(baseline.createdAt)}</span>
          <span>Source scan {formatDate(baseline.sourceScanDate)}</span>
          <span>Fingerprint <code>{shortBaselineFingerprint(baseline.fingerprint)}</code></span>
          <span>Drift {comparison.changeCount}</span>
          <span>Highest drift {formatRiskLabel(comparison.highestSeverity)}</span>
        </div>
      ) : null}
      {baseline.note ? <p className="trusted-baseline-note"><strong>Approval note:</strong> {baseline.note}</p> : null}
      {comparison.changes.length && !compact ? (
        <details className="dependency-details">
          <summary>Trusted baseline drift ({comparison.changeCount})</summary>
          <ul>{comparison.changes.slice(0, 20).map((change, index) => (
            <li key={`${change.changeType}-${change.name || change.path}-${index}`}><strong>{change.changeType}</strong>: {change.name || change.path || "dependency input"}{change.currentValue ? ` → ${change.currentValue}` : ""}</li>
          ))}</ul>
          {comparison.truncated || comparison.changeCount > 20 ? <p className="muted">Additional drift is summarized in the count.</p> : null}
        </details>
      ) : null}
      {viewMode === "history" ? <p className="muted">This historical evidence is unchanged. Changing the active baseline can change the comparison shown here.</p> : null}
      {compact ? (
        <div className="trusted-baseline-actions trusted-baseline-compact-actions">
          {!baseline.configured && approvalEligible && onApprove ? (
            <button type="button" onClick={() => onApprove(scan, false, "")} disabled={mutation.saving}>{mutation.saving ? "Saving..." : "Trust this snapshot"}</button>
          ) : null}
          {baseline.configured && onManage ? <button type="button" className="secondary-button compact-action" onClick={onManage} disabled={mutation.saving}>Manage baseline</button> : null}
          {mutation.error ? <p className="finding-review-message error">{mutation.error}</p> : null}
          {mutation.success ? <p className="finding-review-message success">{mutation.success}</p> : null}
        </div>
      ) : null}
      {canUseFullActions ? (
        <div className="trusted-baseline-actions">
          {!baseline.configured && approvalEligible ? (
            <label className="trusted-baseline-approval">
              Optional approval note
              <textarea value={note} onInput={(event) => setNote(event.currentTarget.value)} maxLength="1000" rows="2" disabled={mutation.saving} />
              <button type="button" onClick={() => onApprove(scan, false, note)} disabled={mutation.saving}>{mutation.saving ? "Saving..." : "Trust this dependency snapshot"}</button>
            </label>
          ) : null}
          {baseline.configured ? (
            <div className="trusted-baseline-buttons">
              {approvalEligible ? <button type="button" onClick={() => onApprove(scan, true, baseline.note)} disabled={mutation.saving}>{mutation.saving ? "Saving..." : "Replace trusted baseline"}</button> : null}
              <button type="button" className="history-view-button" onClick={() => setEditingNote((value) => !value)} disabled={mutation.saving}>Edit note</button>
              <button type="button" className="history-view-button destructive-button" onClick={onClear} disabled={mutation.saving}>Clear trusted baseline</button>
            </div>
          ) : null}
          {editingNote && baseline.configured ? (
            <form className="trusted-baseline-note-form" onSubmit={(event) => { event.preventDefault(); onUpdateNote(note); }}>
              <label>Approval note<textarea value={note} onInput={(event) => setNote(event.currentTarget.value)} maxLength="1000" rows="2" disabled={mutation.saving} /></label>
              <div className="trusted-baseline-buttons">
                <button type="submit" disabled={mutation.saving}>{mutation.saving ? "Saving..." : "Save note"}</button>
                <button type="button" className="history-view-button" onClick={() => { setNote(baseline.note || ""); setEditingNote(false); }} disabled={mutation.saving}>Cancel</button>
              </div>
            </form>
          ) : null}
          {mutation.error ? <p className="finding-review-message error">{mutation.error}</p> : null}
          {mutation.success ? <p className="finding-review-message success">{mutation.success}</p> : null}
        </div>
      ) : null}
    </section>
  );
}

function dependencyFileChanges(fileChanges) {
  const labels = {
    manifestsAdded: "manifest-added",
    manifestsRemoved: "manifest-removed",
    lockfilesAdded: "lockfile-added",
    lockfilesRemoved: "lockfile-removed",
  };
  return Object.entries(labels).flatMap(([key, type]) => (fileChanges?.[key] || []).map((path) => ({ type, path })));
}

function PathDetails({ title, items, recordedCount, emptyText, guidance }) {
  if (items.length === 0) {
    return (
      <div className="scan-detail-empty">
        <strong>{title}</strong>
        <GuidanceBlock guidance={guidance} />
        <span>{recordedCount > 0 ? `${recordedCount} paths recorded; path list unavailable for this older scan.` : emptyText}</span>
      </div>
    );
  }

  return (
    <details className="scan-detail">
      <summary>
        <strong>{title}</strong>
        <span>{items.length} paths</span>
      </summary>
      <GuidanceBlock guidance={guidance} />
      <PathList items={items} />
    </details>
  );
}

function PathSection({ title, items, emptyText, reviewKind, guidance }) {
  const findings = reviewKind ? items.map((item) => metadataFinding(reviewKind, item)) : [];

  return (
    <ScanSection title={title} count={items.length} findings={findings} emptyText={emptyText} guidance={guidance}>
      {reviewKind ? (
        findings.map((finding, index) => <FindingItem finding={finding} key={findingKey(finding, index)} />)
      ) : (
        <PathList items={items} />
      )}
    </ScanSection>
  );
}

function FindingPathSection({ title, items, findings, emptyText, guidance, onReviewFinding, onReopenFinding, findingReviewState = {} }) {
  const count = uniquePaths([...items, ...findings.map((finding) => finding.path)]).length;

  return (
    <ScanSection title={title} count={count} findings={findings} emptyText={emptyText} guidance={guidance}>
      {items.length > 0 ? <PathList items={items} /> : null}
      {findings.map((finding, index) => <FindingItem finding={finding} key={findingKey(finding, index)} onReviewFinding={onReviewFinding} onReopenFinding={onReopenFinding} requestState={findingReviewState[finding.fingerprint]} />)}
    </ScanSection>
  );
}

function LifecycleSection({ items, findings, onReviewFinding, onReopenFinding, findingReviewState = {} }) {
  return (
    <ScanSection title="Lifecycle Scripts" count={items.length} findings={findings} emptyText="No package lifecycle scripts recorded for this scan." guidance={SCAN_GUIDANCE.lifecycleScripts}>
      {items.length > 0 ? (
        <ul className="path-list">
          {items.map((script) => (
            <li key={`${script.path}-${script.script}`}>
              <code>{script.path}</code>
              <span>{script.script}</span>
            </li>
          ))}
        </ul>
      ) : null}
      {findings.map((finding, index) => <FindingItem finding={finding} key={findingKey(finding, index)} onReviewFinding={onReviewFinding} onReopenFinding={onReopenFinding} requestState={findingReviewState[finding.fingerprint]} />)}
    </ScanSection>
  );
}

function FindingSection({ title, findings, emptyText, guidance, onReviewFinding, onReopenFinding, findingReviewState = {} }) {
  return (
    <ScanSection title={title} count={findings.length} findings={findings} emptyText={emptyText} guidance={guidance}>
      {findings.map((finding, index) => <FindingItem finding={finding} key={findingKey(finding, index)} onReviewFinding={onReviewFinding} onReopenFinding={onReopenFinding} requestState={findingReviewState[finding.fingerprint]} />)}
    </ScanSection>
  );
}

function PathList({ items }) {
  return (
    <ul className="path-list">
      {items.map((item, index) => (
        <li key={`${item}-${index}`}><code>{item}</code></li>
      ))}
    </ul>
  );
}

function MetadataSection({ zone, findings, onReviewFinding, onReopenFinding, findingReviewState = {} }) {
  return (
    <ScanSection title="Zone/Metadata Findings" count={findings.length} findings={findings} emptyText="No additional metadata findings." guidance={SCAN_GUIDANCE.zone}>
      <div className="metadata-row">
        <span>Zone</span>
        <strong>{zone || "Unknown"}</strong>
      </div>
      {findings.map((finding, index) => <FindingItem finding={finding} key={findingKey(finding, index)} onReviewFinding={onReviewFinding} onReopenFinding={onReopenFinding} requestState={findingReviewState[finding.fingerprint]} />)}
    </ScanSection>
  );
}

function ScanSection({ title, count, findings, emptyText, guidance, children }) {
  const hasContent = count > 0 || findings.length > 0;
  const highestSeverity = highestFindingSeverity(findings);
  const summary = hasContent ? `${count} ${count === 1 ? "item" : "items"}` : emptyText;

  if (!hasContent) {
    return (
      <article className="scan-card scan-card-empty">
        <ScanSectionHeader title={title} count={count} emptyText={emptyText} severity={highestSeverity} />
        <GuidanceBlock guidance={guidance} />
      </article>
    );
  }

  return (
    <article className="scan-card">
      <ScanSectionHeader title={title} count={count} summary={summary} severity={highestSeverity} />
      <GuidanceBlock guidance={guidance} />
      <div className="scan-card-body">{children}</div>
    </article>
  );
}

function ScanSectionHeader({ title, count, summary, emptyText, severity }) {
  return (
    <div className="scan-card-static-heading">
      <div>
        <h3>{title}</h3>
        <small>{summary || emptyText || `${count} ${count === 1 ? "item" : "items"}`}</small>
      </div>
      {severity ? <span className={`risk risk-${severity}`}>{severity}</span> : null}
    </div>
  );
}

function GuidanceBlock({ guidance }) {
  if (!guidance) return null;

  return (
    <div className="guidance-block">
      <p><strong>Why this matters:</strong> {guidance.why}</p>
      <p><strong>What to check:</strong> {guidance.check}</p>
    </div>
  );
}

function FindingItem({ finding, onReviewFinding, onReopenFinding, requestState = {} }) {
  const detail = normalizeFinding(finding);
  const rawExplanation = finding.explanation && finding.explanation !== detail.why ? finding.explanation : "";
  const [editingReview, setEditingReview] = useState(false);
  const [reviewStatus, setReviewStatus] = useState(finding.review?.status || "expected");
  const [reviewNote, setReviewNote] = useState(finding.review?.note || "");
  const reviewable = Boolean(finding.fingerprint && onReviewFinding && onReopenFinding);

  useEffect(() => {
    setReviewStatus(finding.review?.status || "expected");
    setReviewNote(finding.review?.note || "");
    if (finding.review) setEditingReview(false);
  }, [finding.fingerprint, finding.review?.status, finding.review?.note]);

  return (
    <div className="finding">
      <div className="finding-heading">
        <strong>{detail.title}</strong>
        <span className={`risk risk-${detail.severity}`}>{detail.severity}</span>
        {reviewable ? <span className={`finding-review-status ${finding.review ? "reviewed" : "unreviewed"}`}>{findingReviewLabel(finding.review)}</span> : null}
        <span className="finding-category">{detail.category}</span>
        <code>{detail.path}</code>
      </div>
      <div className="finding-detail">
        <p><strong>Why:</strong> {detail.why}</p>
        <p><strong>Action:</strong> {detail.action}</p>
        {rawExplanation ? <p><strong>Raw detail:</strong> {rawExplanation}</p> : null}
        {detail.evidence ? (
          <div className="finding-evidence">
            <p><strong>Scanner context</strong> Context only; not proof of malicious behavior.</p>
            <div className="finding-evidence-meta">
              <span>Line {detail.evidence.line}</span>
              <span>Rule/pattern <code>{detail.evidence.pattern}</code></span>
              {detail.evidence.matchCount > 1 ? <span>{detail.evidence.matchCount} matches</span> : null}
              {detail.evidence.additionalMatchesOmitted ? <span>Additional matches omitted</span> : null}
            </div>
            <pre><code>{detail.evidence.excerpt}</code></pre>
          </div>
        ) : null}
        {finding.review?.note ? <p className="finding-review-note"><strong>Review reason:</strong> {finding.review.note}</p> : null}
        {reviewable ? (
          <div className="finding-review-controls">
            {!editingReview ? (
              <div className="finding-review-actions">
                <button type="button" className="history-view-button" onClick={() => setEditingReview(true)} disabled={requestState.saving}>
                  {finding.review ? "Edit review" : "Mark reviewed"}
                </button>
                {finding.review ? <button type="button" className="history-view-button" onClick={() => onReopenFinding(finding)} disabled={requestState.saving}>{requestState.saving ? "Saving..." : "Reopen"}</button> : null}
              </div>
            ) : (
              <form className="finding-review-form" onSubmit={(event) => {
                event.preventDefault();
                const controls = event.currentTarget.elements;
                onReviewFinding(finding, controls.reviewStatus.value, controls.reviewNote.value);
              }}>
                <label>
                  Review status
                  <select name="reviewStatus" value={reviewStatus} onChange={(event) => setReviewStatus(event.target.value)} disabled={requestState.saving}>
                    <option value="expected">Reviewed as expected</option>
                    <option value="reviewed">Reviewed</option>
                  </select>
                </label>
                <label>
                  Optional reason
                  <textarea name="reviewNote" value={reviewNote} onChange={(event) => setReviewNote(event.target.value)} maxLength="1000" rows="2" placeholder="Why is this exact finding expected?" disabled={requestState.saving} />
                </label>
                <div className="finding-review-actions">
                  <button type="submit" disabled={requestState.saving}>{requestState.saving ? "Saving..." : "Save review"}</button>
                  <button type="button" className="history-view-button" onClick={() => setEditingReview(false)} disabled={requestState.saving}>Cancel</button>
                </div>
              </form>
            )}
            {requestState.error ? <p className="finding-review-message error">{requestState.error}</p> : null}
            {requestState.success ? <p className="finding-review-message success">{requestState.success}</p> : null}
          </div>
        ) : null}
      </div>
    </div>
  );
}


function FindingWorkbench({ findings = [], scanIdentity, onReviewFinding, onReopenFinding, findingReviewState = {} }) {
  const [reviewStatus, setReviewStatus] = useState("all");
  const [severity, setSeverity] = useState("all");
  const [category, setCategory] = useState("all");
  const [query, setQuery] = useState("");
  const [activeKey, setActiveKey] = useState("");
  const itemRefs = useRef(new Map());
  const items = useMemo(() => buildFindingWorkbenchItems(findings), [findings]);
  const visibleItems = useMemo(() => filterFindingWorkbenchItems(items, {
    reviewStatus,
    severity,
    category,
    query,
  }), [items, reviewStatus, severity, category, query]);
  const options = useMemo(() => findingWorkbenchFilterOptions(items), [items]);
  const progress = useMemo(() => findingWorkbenchProgress(items), [items]);
  const visibleUnresolvedCount = visibleItems.filter((item) => !item.reviewed).length;

  useEffect(() => {
    setActiveKey("");
  }, [scanIdentity]);

  function goToNextUnresolved() {
    const nextKey = nextUnresolvedFindingKey(visibleItems, activeKey);
    if (!nextKey) return;
    setActiveKey(nextKey);
    requestAnimationFrame(() => {
      const target = itemRefs.current.get(nextKey);
      target?.focus({ preventScroll: true });
      target?.scrollIntoView?.({ behavior: "smooth", block: "center" });
    });
  }

  return (
    <section className="finding-workbench" aria-labelledby="finding-workbench-title">
      <div className="finding-workbench-heading">
        <div>
          <h3 id="finding-workbench-title">Finding review workbench</h3>
          <p>Search, filter, and review one priority-ordered queue. Unresolved items stay first.</p>
        </div>
        <div className="finding-workbench-progress" aria-label={`${progress.reviewed} of ${progress.total} findings reviewed`}>
          <strong>{progress.reviewed} / {progress.total}</strong>
          <span>reviewed</span>
          <progress value={progress.reviewed} max={Math.max(progress.total, 1)} />
        </div>
      </div>

      <div className="finding-workbench-filters">
        <label>
          Review status
          <select value={reviewStatus} onChange={(event) => setReviewStatus(event.target.value)}>
            <option value="all">All</option>
            <option value="unresolved">Unresolved</option>
            <option value="reviewed">Reviewed</option>
          </select>
        </label>
        <label>
          Severity
          <select value={severity} onChange={(event) => setSeverity(event.target.value)}>
            <option value="all">All</option>
            {options.severities.map((value) => <option value={value} key={value}>{value}</option>)}
          </select>
        </label>
        <label>
          Category
          <select value={category} onChange={(event) => setCategory(event.target.value)}>
            <option value="all">All</option>
            {options.categories.map((value) => <option value={value} key={value}>{value}</option>)}
          </select>
        </label>
        <label className="finding-workbench-search">
          Search findings
          <input type="search" value={query} onInput={(event) => setQuery(event.target.value)} placeholder="Title or file path" />
        </label>
      </div>

      <div className="finding-workbench-actions">
        <span>{visibleItems.length} visible · {visibleUnresolvedCount} unresolved</span>
        <button type="button" className="secondary-button compact-action" onClick={goToNextUnresolved} disabled={visibleUnresolvedCount === 0}>Next unresolved</button>
      </div>

      <div className="finding-workbench-queue">
        {visibleItems.map((item) => (
          <div
            className={`finding-workbench-item${activeKey === item.key ? " active" : ""}`}
            data-finding-key={item.key}
            aria-current={activeKey === item.key ? "true" : undefined}
            key={item.key}
            ref={(element) => {
              if (element) itemRefs.current.set(item.key, element);
              else itemRefs.current.delete(item.key);
            }}
            tabIndex="-1"
          >
            <FindingItem
              finding={item.finding}
              onReviewFinding={onReviewFinding}
              onReopenFinding={onReopenFinding}
              requestState={findingReviewState[item.finding.fingerprint]}
            />
          </div>
        ))}
        {items.length === 0 ? <p className="good">No findings were recorded for this scan.</p> : null}
        {items.length > 0 && visibleItems.length === 0 ? <p className="muted">No findings match the current filters.</p> : null}
      </div>
    </section>
  );
}

function findingKey(finding, index) {
  return [
    finding.type || "unknown",
    finding.severity || "low",
    finding.path || "unknown-path",
    finding.explanation || "",
    index,
  ].join("|");
}

function ScanComparison({ comparison }) {
  return (
    <section className="scan-comparison">
      <h2>Changed Since Previous Scan</h2>
      {!comparison ? (
        <p className="muted">No previous scan to compare yet.</p>
      ) : (
        <div className="comparison-grid">
          <ComparisonItem label="Risk" value={comparison.riskChange} />
          {comparison.coverageChange ? <ComparisonItem label="Coverage" value={comparison.coverageChange} /> : null}
          <ComparisonItem label="Findings" value={comparison.findingDelta} />
          <ComparisonItem label="Reviewed files" value={comparison.reviewedDelta} />
          <ComparisonItem label="Ignored files" value={comparison.ignoredDelta} />
          <div className="comparison-summary">
            <strong>Finding types</strong>
            <span>{comparison.typeSummary}</span>
          </div>
        </div>
      )}
    </section>
  );
}

function ComparisonItem({ label, value }) {
  return (
    <div className="comparison-item">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function TrustProfileContext({ context }) {
  return (
    <section className="trust-context">
      <h2>Project Expectations Context</h2>
      {!context.configured ? (
        <p className="muted">No Project Expectations are approved. Scan observations and findings remain unchanged.</p>
      ) : (
        <div className="trust-context-list">
          <TrustContextGroup title="Package managers" items={context.packageManagerStates} />
          <TrustContextGroup title="Ecosystems" items={context.ecosystemStates} />
          <TrustContextGroup title="Manifests" items={context.manifests} />
          <TrustContextGroup title="Lockfiles" items={context.lockfiles} />
          <TrustContextGroup title="Lifecycle scripts" items={context.lifecycleScripts} />
          <TrustContextGroup title="Reviewed paths" items={context.reviewedPaths} />
          <TrustContextGroup title="Ignored paths" items={context.ignoredPaths} />
          <div className="trust-context-item">
            <strong>Risk tolerance (review context only)</strong>
            <span>{context.riskTolerance}; scanner findings, raw risk, dependency approval, and completion are unchanged.</span>
          </div>
          {context.notes ? <p className="trust-notes">{context.notes}</p> : null}
        </div>
      )}
    </section>
  );
}

function TrustContextGroup({ title, items }) {
  if (!items.length) return null;
  return (
    <div className="trust-context-group">
      <strong>{title}</strong>
      {items.map((item) => (
        <div className="trust-context-item" key={`${title}-${item.status}-${item.path}`}>
          <span className={`trust-status ${trustStatusClass(item.status)}`}>{item.status}</span>
          <span>{item.path}</span>
        </div>
      ))}
    </div>
  );
}

function AgentGenerator({ form, updateField, preview, exists, onPreview, onWrite, open, onOpenChange }) {
  return (
    <details className="panel section-toggle" open={open} onToggle={(event) => onOpenChange(event.currentTarget.open)}>
      <summary className="section-summary">
        <span className="section-caret" aria-hidden="true"></span>
        <div>
          <h2>AGENTS.md Generator</h2>
          <p className="muted">{exists ? "AGENTS.md exists. Writing requires confirmation." : "Preview before writing anything to disk."}</p>
        </div>
      </summary>
      <div className="section-body">
      <form onSubmit={onPreview} className="grid-form">
        <textarea value={form.project_purpose} onChange={(event) => updateField("project_purpose", event.target.value)} placeholder="Project purpose" rows="4" />
        <textarea value={form.project_rules} onChange={(event) => updateField("project_rules", event.target.value)} placeholder="Project rules" rows="4" />
        <textarea value={form.build_commands} onChange={(event) => updateField("build_commands", event.target.value)} placeholder="Build commands" rows="4" />
        <textarea value={form.test_commands} onChange={(event) => updateField("test_commands", event.target.value)} placeholder="Test commands" rows="4" />
        <textarea value={form.security_notes} onChange={(event) => updateField("security_notes", event.target.value)} placeholder="Security notes" rows="4" />
        <div className="actions">
          <button type="submit">Preview</button>
          <button type="button" onClick={onWrite} disabled={!preview}>Write AGENTS.md</button>
        </div>
      </form>
      {preview ? <pre className="preview">{preview}</pre> : null}
      </div>
    </details>
  );
}

function Notes({ notes, noteBody, setNoteBody, onAdd, open, onOpenChange }) {
  return (
    <details className="panel section-toggle" open={open} onToggle={(event) => onOpenChange(event.currentTarget.open)}>
      <summary className="section-summary">
        <span className="section-caret" aria-hidden="true"></span>
        <h2>Project Notes</h2>
      </summary>
      <div className="section-body">
      <form onSubmit={onAdd} className="note-form">
        <textarea value={noteBody} onChange={(event) => setNoteBody(event.target.value)} placeholder="Add a note" rows="3" />
        <button type="submit">Add Note</button>
      </form>
      <div className="notes-list">
        {notes.map((note) => (
          <article className="note" key={note.id}>
            <p>{note.body}</p>
            <time>{formatDate(note.created_at)}</time>
          </article>
        ))}
        {notes.length === 0 ? <p className="muted">No notes yet.</p> : null}
      </div>
      </div>
    </details>
  );
}

function History({ scans, selectedScanId, onSelectScan, open, onOpenChange }) {
  return (
    <details className="panel section-toggle" open={open} onToggle={(event) => onOpenChange(event.currentTarget.open)}>
      <summary className="section-summary">
        <span className="section-caret" aria-hidden="true"></span>
        <h2>Scan History</h2>
      </summary>
      <div className="section-body">
      <div className="history-list">
        {scans.map((scan, index) => {
          const previousScan = scans[index + 1];
          const riskChanged = previousScan && previousScan.overall_risk !== scan.overall_risk;
          const selected = selectedScanId === scan.id;
          const completeness = normalizeScanCompleteness(scan);
          const reviewSummary = findingReviewSummary(scan);
          return (
          <div className={`history-row ${selected ? "selected-history-row" : ""}`} key={scan.id}>
            <div className="history-primary">
              <strong>{formatDate(scan.scan_date)}</strong>
              <span>{formatFindingSummary(scan.findingSummary)}</span>
            </div>
            <span className={`risk history-risk risk-${scan.overall_risk}`}>{scan.overall_risk === "none" ? findingCountLabel(scan.findingCount ?? scan.findings.length) : `Risk: ${scan.overall_risk}`}</span>
            <div className="history-counts">
              {scan.overall_risk !== "none" ? <span>{findingCountLabel(scan.findingCount ?? scan.findings.length)}</span> : null}
              <span>{scan.reviewedFileCount ?? 0} reviewed</span>
              <span>{scan.ignoredFileCount ?? 0} ignored</span>
              <span>{reviewSummary.unreviewedFindingCount} unresolved</span>
              <span>{reviewSummary.reviewedFindingCount} finding reviews</span>
              <span>{projectCoverageText(completeness)}</span>
            </div>
            <button type="button" className="history-view-button" onClick={() => onSelectScan(selected ? null : scan.id)}>
              {selected ? "Viewing" : "View"}
            </button>
            {riskChanged ? <span className="risk-change">Changed from {previousScan.overall_risk}</span> : null}
          </div>
          );
        })}
        {scans.length === 0 ? <p className="muted">No scans saved yet.</p> : null}
      </div>
      </div>
    </details>
  );
}

async function api(path, options = {}) {
  return requestApi(path, options);
}

function mergeActivityEvents(current, next) {
  const events = [...current];
  const seen = new Set(current.map((event) => event.eventId));
  for (const event of next) {
    if (seen.has(event.eventId)) continue;
    seen.add(event.eventId);
    events.push(event);
  }
  return events;
}

function buildScanReport(result) {
  const findings = result?.findings || [];
  const lifecycleScripts = scanArray(result, "lifecycleScripts");
  const secretFiles = scanArray(result, "secretFiles");
  const ignoredFiles = scanArray(result, "ignoredFiles");
  const manifests = scanArray(result, "manifests");
  const lockfilePathsFromFindings = findings
    .filter((finding) => finding.type === "lockfile")
    .map((finding) => finding.path);
  const storedLockfiles = scanArray(result, "lockfiles");
  const lockfiles = storedLockfiles.length ? storedLockfiles : uniquePaths(lockfilePathsFromFindings);
  const secretPaths = new Set(secretFiles);
  const lifecyclePaths = new Set(lifecycleScripts.map((script) => script.path));
  const lockfilePaths = new Set(lockfiles);

  const secretFindings = findings.filter((finding) => finding.type === "secret-looking-file" || secretPaths.has(finding.path));
  const executableFindings = findings.filter((finding) => finding.type === "executable-or-script-file");
  const lifecycleFindings = findings.filter((finding) => finding.type === "package-lifecycle-script" || lifecyclePaths.has(finding.path));
  const lockfileFindings = findings.filter((finding) => finding.type === "lockfile" || lockfilePaths.has(finding.path));
  const findingTypeCounts = summarizeFindingTypes(findings);
  const metadataFindings = findings.filter((finding) => {
    if (String(finding.type || "").startsWith("dependency-")) return false;
    if (finding.type === "secret-looking-file" || finding.type === "executable-or-script-file") return false;
    if (finding.type === "package-lifecycle-script" || lifecyclePaths.has(finding.path)) return false;
    if (finding.type === "lockfile" || lockfilePaths.has(finding.path)) return false;
    return true;
  });

  const reviewedFileCount = result?.reviewedFileCount ?? scanArray(result, "reviewedFiles").length;
  const dependencyFindings = findings.filter((finding) => String(finding.type || "").startsWith("dependency-"));
  const storedReviewedFiles = scanArray(result, "reviewedFiles");
  const reviewedFiles = storedReviewedFiles.length
    ? storedReviewedFiles
    : reviewedFileCount > 0
      ? []
      : uniquePaths([...findings.map((finding) => finding.path), ...manifests, ...lockfiles, ...secretFiles]);

  return {
    totalFindings: result?.findingCount ?? findings.length,
    reviewedFileCount,
    ignoredFileCount: result?.ignoredFileCount ?? ignoredFiles.length,
    reviewedFiles,
    manifests,
    lockfiles,
    lifecycleScripts,
    lifecycleFindings,
    lockfileFindings,
    findingTypeCounts,
    secretFiles,
    secretFindings,
    executableFindings,
    metadataFindings,
    dependencyFindings,
    dependencyTrust: normalizeDependencyTrust(result?.dependencyTrust, result?.trustedDependencyBaseline),
    reviewSummary: findingReviewSummary(result),
    ignoredFiles,
    zone: result?.zone || "Unknown",
    completeness: normalizeScanCompleteness(result),
  };
}

function scanArray(result, field) {
  const value = result?.[field];
  return Array.isArray(value) ? value : [];
}

function profileList(profile, field) {
  return scanArray(profile, field);
}

function scanCategoryRows(report) {
  return [
    { label: "Manifests", count: report.manifests.length, findingCategory: true },
    { label: "Lockfiles", count: report.lockfiles.length, findingCategory: true },
    { label: "Lifecycle Scripts", count: report.lifecycleScripts.length, findingCategory: true },
    { label: "Secret Findings", count: report.secretFindings.length, findingCategory: true },
    { label: "Executable Files", count: report.executableFindings.length, findingCategory: true },
    { label: "Zone / Metadata Findings", count: report.metadataFindings.length, findingCategory: true },
    { label: "Reviewed Files", count: report.reviewedFileCount, findingCategory: false },
    { label: "Ignored Files", count: report.ignoredFileCount, findingCategory: false },
  ];
}

function categoryStatus(row, completeness) {
  if (!row.findingCategory) return { label: "Count", className: "status-count" };
  if (row.count > 0) return { label: "Review", className: "status-review" };
  if (!completeness.known) return { label: "Unknown", className: "status-unknown" };
  if (!completeness.complete) return { label: "Not verified", className: "status-review" };
  return { label: "Clean", className: "status-clean" };
}

function buildTrustProfileContext(report, profile = EMPTY_TRUST_PROFILE) {
  const normalized = normalizeProjectExpectations(profile);
  const expectedManifestFiles = scanArray(normalized, "expectedManifestFiles");
  const expectedLockfiles = scanArray(normalized, "expectedLockfiles");
  const allowedLifecycleScripts = scanArray(normalized, "allowedLifecycleScripts");
  const reviewedPaths = scanArray(normalized, "reviewedPaths");
  const ignoredPaths = scanArray(normalized, "ignoredPaths");
  const packageManagers = scanArray(normalized, "trustedPackageManagers");
  const ecosystems = scanArray(normalized, "expectedEcosystems");
  const configured = trustProfileConfigured(normalized);
  const scanReliable = report.completeness.known && report.completeness.complete;
  const dependencyReliable = scanReliable
    && report.dependencyTrust.available
    && report.dependencyTrust.status === "complete";

  return {
    configured,
    packageManagers,
    ecosystems,
    packageManagerStates: statusForObservedExpectations(
      report.dependencyTrust.packageManagers,
      packageManagers,
      dependencyReliable,
    ),
    ecosystemStates: statusForObservedExpectations(
      report.dependencyTrust.ecosystems,
      ecosystems,
      dependencyReliable,
    ),
    riskTolerance: normalized.riskTolerance || "normal",
    notes: normalized.notes || "",
    manifests: statusForObservedExpectations(report.manifests, expectedManifestFiles, scanReliable),
    lockfiles: statusForObservedExpectations(report.lockfiles, expectedLockfiles, scanReliable),
    lifecycleScripts: lifecycleExpectationStates(
      report.lifecycleScripts,
      allowedLifecycleScripts,
      scanReliable,
    ),
    reviewedPaths: statusForProfilePaths(reviewedPaths, report.reviewedFiles, report.reviewedFileCount, scanReliable),
    ignoredPaths: statusForProfilePaths(ignoredPaths, report.ignoredFiles, report.ignoredFileCount, scanReliable),
  };
}

function trustProfileConfigured(profile) {
  return TRUST_PROFILE_FIELDS.some((field) => scanArray(profile, field).length > 0)
    || (profile.riskTolerance && profile.riskTolerance !== "normal")
    || Boolean(profile.notes);
}

function statusForObservedExpectations(foundPaths, expectedPaths, reliable) {
  const observed = foundPaths.map((path) => ({
    status: pathMatchesAny(path, expectedPaths) ? "User approved" : reliable && expectedPaths.length ? "Changed" : "Observed",
    path,
  }));
  const missing = expectedPaths
    .filter((expected) => !foundPaths.some((path) => pathMatchesExpected(path, expected)))
    .map((path) => ({
      status: reliable ? "Changed" : "User approved",
      path: reliable
        ? `${path} (approved but not observed)`
        : `${path} (current reliable observation unavailable)`,
    }));
  return [...observed, ...missing];
}

function lifecycleExpectationStates(scripts, approvedScripts, reliable) {
  const observedNames = scripts.map((script) => script.script).filter(Boolean);
  const observed = scripts.map((script) => ({
    status: approvedScripts.includes(script.script)
      ? "User approved"
      : reliable && approvedScripts.length
        ? "Changed"
        : "Observed",
    path: `${script.path || "Unknown path"}: ${script.script || "unknown script"}`,
  }));
  const missing = approvedScripts
    .filter((approved) => !observedNames.includes(approved))
    .map((approved) => ({
      status: reliable ? "Changed" : "User approved",
      path: reliable
        ? `${approved} (approved but not observed)`
        : `${approved} (current reliable observation unavailable)`,
    }));
  return [...observed, ...missing];
}

function statusForProfilePaths(profilePaths, scanPaths, recordedCount = scanPaths.length, reliable = false) {
  if (!reliable || (!scanPaths.length && recordedCount > 0)) {
    return profilePaths.map((path) => ({
      status: "User approved",
      path: `${path} (current reliable observation unavailable)`,
    }));
  }
  return profilePaths.map((path) => ({
    status: scanPaths.some((scanPath) => pathMatchesExpected(scanPath, path)) ? "User approved" : "Changed",
    path,
  }));
}

function pathMatchesAny(path, expectedPaths) {
  return expectedPaths.some((expected) => pathMatchesExpected(path, expected));
}

function pathMatchesExpected(path, expected) {
  const normalizedPath = normalizePath(path);
  const normalizedExpected = normalizePath(expected);
  return normalizedPath === normalizedExpected || normalizedPath.endsWith(`/${normalizedExpected}`);
}

function normalizePath(path) {
  return String(path || "").replaceAll("\\", "/").replace(/^\/+/, "").trim();
}

function trustStatusClass(status) {
  return String(status || "").toLowerCase().replaceAll(" ", "-");
}

function uniquePaths(paths) {
  return Array.from(new Set(paths.filter(Boolean)));
}

function metadataFinding(type, path) {
  return {
    type,
    severity: "low",
    path,
  };
}

function highestFindingSeverity(findings) {
  const order = { high: 3, medium: 2, low: 1, none: 0 };
  const highest = findings.reduce((highest, finding) => {
    const severity = finding.severity || "low";
    return order[severity] > order[highest] ? severity : highest;
  }, "none");
  return highest === "none" ? "" : highest;
}

function buildRiskReasons(report, risk) {
  if (!report.completeness.known) {
    return [unknownCoverageMessage(report), "Run a new scan to verify current coverage."];
  }

  if (!report.completeness.complete) {
    return [report.totalFindings === 0
      ? "No findings were recorded, but this scan has inspection gaps."
      : `${report.totalFindings} ${report.totalFindings === 1 ? "finding was" : "findings were"} recorded, and inspection gaps remain.`];
  }

  if (risk === "high" || risk === "medium") {
    const contributors = formatTopFindingTypes(report.findingTypeCounts);
    if (contributors) return [`Main contributors: ${contributors}.`];
    if (report.manifests.length > 0 && report.lockfiles.length === 0) return ["Manifest files were found without matching lockfiles."];
    return ["Risk is based on scanner metadata for this project."];
  }

  if (risk === "low") {
    const reasons = [];
    if (report.lifecycleScripts.length === 0) reasons.push("No package lifecycle scripts found.");
    if (report.secretFindings.length === 0) reasons.push("No secret-looking files found.");
    if (report.executableFindings.length === 0) reasons.push("No executable files found.");
    if (report.manifests.length > 0 || report.lockfiles.length > 0) reasons.push("Manifests and lockfiles were reviewed.");
    if (report.ignoredFiles.length > 0) reasons.push("Ignored files are neutral and not counted as suspicious by default.");
    return reasons.length > 0 ? reasons : ["Only low-risk review prompts were found."];
  }

  if (report.ignoredFiles.length > 0) return ["No scanner findings contributed to risk. Ignored files are neutral by default."];
  return ["No scanner findings contributed to risk."];
}

function overallRiskReasonTone(report, risk) {
  if (!report.completeness.known || !report.completeness.complete) return "warning";
  const unresolved = report.reviewSummary.unreviewedFindingCount > 0;
  const severity = report.reviewSummary.highestUnreviewedSeverity;
  if (unresolved && severity === "high") return "high";
  if (unresolved) return "warning";
  return risk === "none" ? "success" : "neutral";
}

function riskIndicatorSymbol(tone) {
  if (tone === "success") return "✓";
  if (tone === "neutral") return "•";
  return "!";
}

function unknownCoverageMessage(report) {
  return report.totalFindings === 0
    ? "No findings recorded; coverage unknown."
    : `${report.totalFindings} ${report.totalFindings === 1 ? "finding was" : "findings were"} recorded; coverage unknown.`;
}

function findingAbsenceDetail(completeness) {
  if (!completeness.known) return "No findings recorded; coverage unknown";
  if (!completeness.complete) return "No findings recorded; scan incomplete";
  return "No findings detected";
}

function riskSummaryText(report, risk) {
  if (!report.completeness.known) return `${unknownCoverageMessage(report)} Run a new scan to verify current coverage.`;
  if (!report.completeness.complete && report.totalFindings === 0) return "No findings recorded; scan incomplete.";
  return risk === "none"
    ? "No scanner findings contributed to risk."
    : "Review the current scan before running project code.";
}

function summarizeFindingTypes(findings) {
  return findings.reduce((summary, finding) => {
    const type = finding.type || "unknown";
    summary[type] = (summary[type] || 0) + 1;
    return summary;
  }, {});
}

function formatTopFindingTypes(summary) {
  const entries = Object.entries(summary || {})
    .filter(([, count]) => count > 0)
    .sort(([, leftCount], [, rightCount]) => rightCount - leftCount)
    .slice(0, 3);

  return entries.map(([type, count]) => `${type}: ${count}`).join(", ");
}

function coverageLabel(completeness) {
  if (!completeness.known) return "Coverage unknown";
  return completeness.complete ? "Complete scan" : "Incomplete scan";
}

function coverageDetail(completeness) {
  if (!completeness.known) return "Older scan lacks coverage metadata";
  return completeness.complete
    ? "No inspection gaps recorded"
    : `${completeness.issueCount} inspection ${completeness.issueCount === 1 ? "issue" : "issues"}`;
}

function projectCoverageLabel(project) {
  if (!project?.last_scan_time) return "Coverage: Not scanned";
  return projectCoverageText(normalizeScanCompleteness({ scanCompleteness: project.last_scan_completeness }));
}

function projectFindingRiskLabel(project) {
  if (project?.scan_state === "not_scanned" || !project?.last_scan_time) return "Findings: Not scanned";
  return project.last_risk_level === "none"
    ? "Findings: None recorded"
    : `Risk: ${formatRiskLabel(project.last_risk_level)}`;
}

function projectCoverageText(completeness) {
  if (!completeness.known) return "Coverage: Unknown";
  return completeness.complete ? "Coverage: Complete" : "Coverage: Incomplete";
}

function findingCountLabel(count) {
  return `${count} ${count === 1 ? "finding" : "findings"}`;
}

function coverageHeaderLabel(completeness) {
  if (!completeness.known) return "Coverage unknown";
  return completeness.complete ? "Complete coverage" : "Incomplete coverage";
}

function coverageState(completeness) {
  if (!completeness.known) return "unknown";
  return completeness.complete ? "complete" : "incomplete";
}

function scanActivityLabel(scan) {
  const completeness = normalizeScanCompleteness(scan);
  if (!completeness.known) return "Legacy scan recorded";
  return completeness.complete ? "Scan completed" : "Incomplete scan recorded";
}

function buildScanComparisonFor(scan, scans) {
  if (!scan || !scans || scans.length < 2) return null;

  const scanIndex = scans.findIndex((entry) => entry.id === scan.id);
  if (scanIndex < 0 || scanIndex + 1 >= scans.length) return null;

  const latest = scans[scanIndex];
  const previous = scans[scanIndex + 1];
  const latestCompleteness = normalizeScanCompleteness(latest);
  const previousCompleteness = normalizeScanCompleteness(previous);
  const coverageComparable = latestCompleteness.known && previousCompleteness.known;
  const riskUnchanged = latest.overall_risk === previous.overall_risk;
  const riskChange = riskUnchanged
    ? "Risk unchanged"
    : `${formatRiskLabel(previous.overall_risk)} -> ${formatRiskLabel(latest.overall_risk)}`;
  return {
    riskChange: coverageComparable
      ? riskChange
      : riskUnchanged
        ? "Recorded risk unchanged; coverage comparison unavailable"
        : `Recorded risk: ${riskChange}; coverage comparison unavailable`,
    coverageChange: coverageComparable
      ? `${coverageHeaderLabel(previousCompleteness)} -> ${coverageHeaderLabel(latestCompleteness)}`
      : "Unavailable because at least one scan lacks coverage metadata",
    findingDelta: formatCountDelta(scanFindingCount(latest) - scanFindingCount(previous), "finding", "findings"),
    reviewedDelta: formatCountDelta(scanReviewedCount(latest) - scanReviewedCount(previous), "reviewed file", "reviewed files"),
    ignoredDelta: formatCountDelta(scanIgnoredCount(latest) - scanIgnoredCount(previous), "ignored file", "ignored files"),
    typeSummary: formatFindingTypeDelta(latest.findingSummary, previous.findingSummary),
  };
}

function isTransientSuccessMessage(value) {
  return /^(?:Scan complete\.|AGENTS\.md preview generated\.|Created |Registered |Workspace root changed\.|Project metadata saved\.|Saved UI state reset\.)/.test(value || "");
}

function formatRiskLabel(risk) {
  return (risk || "none").toUpperCase();
}

function scanFindingCount(scan) {
  return scan.findingCount ?? scan.findings?.length ?? 0;
}

function scanReviewedCount(scan) {
  return scan.reviewedFileCount ?? 0;
}

function scanIgnoredCount(scan) {
  return scan.ignoredFileCount ?? 0;
}

function formatCountDelta(delta, singular, plural) {
  if (delta === 0) return "no change";
  const label = Math.abs(delta) === 1 ? singular : plural;
  return `${delta > 0 ? "+" : ""}${delta} ${label}`;
}

function formatFindingTypeDelta(latestSummary = {}, previousSummary = {}) {
  const types = Array.from(new Set([...Object.keys(latestSummary || {}), ...Object.keys(previousSummary || {})])).sort();
  const changes = types
    .map((type) => [type, (latestSummary?.[type] || 0) - (previousSummary?.[type] || 0)])
    .filter(([, delta]) => delta !== 0)
    .map(([type, delta]) => `${type}: ${delta > 0 ? "+" : ""}${delta}`);

  return changes.length > 0 ? changes.join(", ") : "No finding-type changes";
}

function exportScanReport(content) {
  const blob = new Blob([content], { type: "text/markdown;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "scan-report.md";
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function formatDate(value) {
  if (!value) return "Never";
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
}

function formatFindingSummary(summary) {
  if (!summary || Object.keys(summary).length === 0) return "No finding types recorded";
  return Object.entries(summary)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([type, count]) => `${type}: ${count}`)
    .join(", ");
}

if (!import.meta.env.SSR) {
  createRoot(document.getElementById("root")).render(<App />);
}
