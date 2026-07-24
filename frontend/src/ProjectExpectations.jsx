import React, { useEffect, useMemo, useState } from "react";
import {
  acceptExpectationSuggestion,
  buildProjectExpectationsViewModel,
  dismissExpectationSuggestion,
  editApprovedExpectations,
  normalizeProjectExpectations,
  provenanceLabel,
  removeApprovedExpectation,
} from "./projectExpectations.js";
import {
  dependencyStatusDescription,
  dependencyStatusLabel,
} from "./dependencyTrust.js";

const STATE_LABELS = {
  observed: "Observed",
  suggested: "Suggested",
  approved: "User approved",
  missing: "Missing",
  changed: "Changed",
};

export function ProjectExpectationsPanel({
  profile,
  report,
  scan,
  message,
  onSave,
  onOpenReports,
}) {
  const normalizedProfile = useMemo(() => normalizeProjectExpectations(profile), [profile]);
  const model = useMemo(
    () => buildProjectExpectationsViewModel({ profile: normalizedProfile, report, scan }),
    [normalizedProfile, report, scan],
  );
  const [editingField, setEditingField] = useState("");
  const [fieldDraft, setFieldDraft] = useState("");
  const [contextDraft, setContextDraft] = useState({
    riskTolerance: normalizedProfile.riskTolerance,
    notes: normalizedProfile.notes,
  });
  const [localMessage, setLocalMessage] = useState("");

  useEffect(() => {
    setEditingField("");
    setFieldDraft("");
    setContextDraft({
      riskTolerance: normalizedProfile.riskTolerance,
      notes: normalizedProfile.notes,
    });
    setLocalMessage("");
  }, [normalizedProfile.project_path]);

  useEffect(() => {
    setContextDraft({
      riskTolerance: normalizedProfile.riskTolerance,
      notes: normalizedProfile.notes,
    });
  }, [normalizedProfile.riskTolerance, normalizedProfile.notes]);

  function beginEdit(field) {
    setEditingField(field.field);
    setFieldDraft(field.approved.map((item) => item.value).join("\n"));
    setLocalMessage("");
  }

  function saveField(event, field) {
    event.preventDefault();
    const values = fieldDraft.split(/[\n,]/).map((item) => item.trim()).filter(Boolean);
    onSave(editApprovedExpectations(normalizedProfile, field.field, values));
    setEditingField("");
    setFieldDraft("");
  }

  function accept(field, value) {
    onSave(acceptExpectationSuggestion(normalizedProfile, field, value));
    setLocalMessage(`Accepted ${value} as one project expectation.`);
  }

  function dismiss(field, value) {
    onSave(dismissExpectationSuggestion(normalizedProfile, field, value));
    setLocalMessage(`Dismissed the ${value} suggestion. The scan observation was not changed.`);
  }

  function remove(field, value) {
    onSave(removeApprovedExpectation(normalizedProfile, field, value));
    setLocalMessage(`Removed ${value} from approved expectations. Scan observations were not changed.`);
  }

  function saveContext(event) {
    event.preventDefault();
    onSave({
      ...normalizedProfile,
      riskTolerance: contextDraft.riskTolerance,
      notes: contextDraft.notes,
    });
  }

  return (
    <section className="panel project-expectations-panel" id="project-expectations">
      <div className="panel-heading project-expectations-heading">
        <div>
          <h2>Project Expectations</h2>
          <p className="muted">
            Review context for the selected project folder inside this workspace. Observations and suggestions are not approvals.
          </p>
        </div>
        <div className="expectation-legend" aria-label="Expectation state legend">
          {Object.entries(STATE_LABELS).map(([state, label]) => (
            <span className={`expectation-state expectation-state-${state}`} key={state}>{label}</span>
          ))}
        </div>
      </div>

      <div className="expectations-safety-note">
        <strong>Context, not a verdict</strong>
        <p>
          Accepting an expectation never suppresses findings, changes severity, reviews evidence, approves dependencies,
          changes coverage, or establishes that this project is safe.
        </p>
      </div>

      <div className="expectation-field-list">
        {model.fields.map((field) => (
          <article className={`expectation-field expectation-field-${field.state}`} key={field.field}>
            <header className="expectation-field-heading">
              <div>
                <h3>{field.label}</h3>
                <p>{field.description}</p>
              </div>
              <span className={`expectation-state expectation-state-${field.state}`}>{STATE_LABELS[field.state]}</span>
            </header>

            <div className="expectation-columns">
              <ExpectationValueGroup title="User approved" empty="No approved values.">
                {field.approved.map((item) => (
                  <div className="expectation-approved-item" key={item.value}>
                    <div>
                      <code>{item.value}</code>
                      <span>{provenanceLabel(item.provenance)}</span>
                    </div>
                    <button
                      type="button"
                      className="text-button destructive-text-button"
                      onClick={() => remove(field.field, item.value)}
                    >
                      Remove
                    </button>
                  </div>
                ))}
              </ExpectationValueGroup>

              <ExpectationValueGroup
                title="Observed in displayed scan"
                empty={scan ? "Nothing recorded for this field." : "No scan available."}
              >
                {field.observed.map((item) => (
                  <div className="expectation-observed-item" key={`${item.value}-${item.detail}`}>
                    <code>{item.value}</code>
                    {item.detail ? <span>{item.detail}</span> : null}
                  </div>
                ))}
                {field.observedOmittedCount > 0 ? (
                  <p>{field.observedOmittedCount} additional observed values omitted from this bounded view.</p>
                ) : null}
              </ExpectationValueGroup>
            </div>

            {field.suggestions.length > 0 ? (
              <div className="expectation-suggestions">
                <strong>Inert suggestions</strong>
                <p>Derived from reliable scan metadata. Accept or dismiss one value at a time.</p>
                {field.suggestions.map((suggestion) => (
                  <div className="expectation-suggestion" key={suggestion}>
                    <code>{suggestion}</code>
                    <div>
                      <button type="button" onClick={() => accept(field.field, suggestion)}>Accept</button>
                      <button type="button" className="secondary-button" onClick={() => dismiss(field.field, suggestion)}>Dismiss</button>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="expectation-reliability">{field.reliabilityMessage}</p>
            )}

            {field.state === "changed" ? (
              <div className="expectation-changed-note">
                <p>The latest reliable observation differs from the approved values. Nothing was overwritten.</p>
                <button
                  type="button"
                  className="secondary-button compact-action"
                  onClick={() => setLocalMessage("Approved values retained. The current observation remains marked Changed.")}
                >
                  Retain approved values
                </button>
              </div>
            ) : null}

            {editingField === field.field ? (
              <form className="expectation-editor" onSubmit={(event) => saveField(event, field)}>
                <label>
                  Approved values, one per line
                  <textarea value={fieldDraft} onInput={(event) => setFieldDraft(event.target.value)} rows="3" />
                </label>
                <div className="actions">
                  <button type="submit">Save field</button>
                  <button type="button" className="secondary-button" onClick={() => setEditingField("")}>Cancel</button>
                </div>
              </form>
            ) : (
              <button type="button" className="secondary-button compact-action" onClick={() => beginEdit(field)}>
                Edit manually
              </button>
            )}

            {field.dismissedCount > 0 ? (
              <p className="expectation-dismissed-count">
                {field.dismissedCount} {field.dismissedCount === 1 ? "suggestion" : "suggestions"} dismissed for this field.
              </p>
            ) : null}
          </article>
        ))}
      </div>

      <section className="approved-dependency-separation" aria-labelledby="approved-dependency-title">
        <div>
          <h3 id="approved-dependency-title">Approved dependency snapshot</h3>
          <p>
            Dependency approval is independent. Project Expectations do not approve package versions, sources, integrity,
            or changes.
          </p>
        </div>
        <div>
          <strong>{model.dependency.label}</strong>
          <span>Current analysis: {dependencyStatusLabel(model.dependency.trust)}.</span>
          <span>{dependencyStatusDescription(model.dependency.trust)}</span>
          <button type="button" className="secondary-button compact-action" onClick={onOpenReports}>Review dependencies in Reports</button>
        </div>
      </section>

      <form className="expectation-review-context" onSubmit={saveContext}>
        <div>
          <h3>Review context</h3>
          <p>
            Risk tolerance is a personal review note only. It does not alter scanner findings, raw risk, evidence,
            dependency approval, coverage, or review completion.
          </p>
        </div>
        <label>
          Risk tolerance
          <select
            value={contextDraft.riskTolerance}
            onChange={(event) => setContextDraft((current) => ({ ...current, riskTolerance: event.target.value }))}
          >
            <option value="cautious">cautious</option>
            <option value="normal">normal</option>
            <option value="permissive">permissive</option>
          </select>
        </label>
        <label className="expectation-notes-field">
          Reviewed safety notes
          <textarea
            value={contextDraft.notes}
            onInput={(event) => setContextDraft((current) => ({ ...current, notes: event.target.value }))}
            rows="2"
            placeholder="Optional local review notes"
          />
        </label>
        <button type="submit">Save review context</button>
      </form>

      {(message || localMessage) ? (
        <p className="expectation-save-message" role="status">{message || localMessage}</p>
      ) : null}
    </section>
  );
}

function ExpectationValueGroup({ title, empty, children }) {
  const items = React.Children.toArray(children);
  return (
    <section className="expectation-value-group">
      <strong>{title}</strong>
      {items.length > 0 ? <div>{items}</div> : <p>{empty}</p>}
    </section>
  );
}
