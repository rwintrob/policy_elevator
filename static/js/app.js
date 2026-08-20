/* JIT Org Policy Elevator Dashboard JavaScript Client */

let requestsData = [];
let auditData = [];
let timerInterval = null;

// Identity & Domain Eligibility Cache
let eligibilityCache = {};

// User Identity Management
function getCurrentUserEmail() {
    const saved = localStorage.getItem("jit_user_email");
    if (saved && saved.trim() !== "") {
        return saved.trim();
    }
    const badgeElem = document.getElementById("current-user-text");
    if (badgeElem && badgeElem.innerText.trim() !== "" && badgeElem.innerText.trim() !== "engineer@company.com") {
        return badgeElem.innerText.trim();
    }
    return "admin@rwintrob.altostrat.com";
}

async function checkIdentityEligibility(email) {
    if (!email || email.trim() === "") {
        return {
            email: "",
            is_eligible_requester: false,
            is_eligible_approver: false,
            domain: "",
            domain_allowed: false,
            status: "INELIGIBLE",
            message: "Email identity is required."
        };
    }
    const cleanEmail = email.trim().toLowerCase();
    if (eligibilityCache[cleanEmail]) {
        return eligibilityCache[cleanEmail];
    }
    try {
        const res = await fetch(`/api/identity/check?email=${encodeURIComponent(cleanEmail)}`);
        if (res.ok) {
            const data = await res.json();
            eligibilityCache[cleanEmail] = data;
            return data;
        }
    } catch (err) {
        console.warn("Eligibility check request error:", err);
    }
    // Fallback client check
    const isAllowed = cleanEmail.endsWith("@rwintrob.altostrat.com") || cleanEmail.endsWith("@altostrat.com");
    return {
        email: cleanEmail,
        is_eligible_requester: isAllowed,
        is_eligible_approver: isAllowed,
        domain: cleanEmail.split("@")[1] || "",
        domain_allowed: isAllowed,
        status: isAllowed ? "ELIGIBLE" : "INELIGIBLE",
        message: isAllowed 
            ? "Identity domain is authorized." 
            : "Identity domain is not in the authorized organization list."
    };
}

async function updateActiveUserEligibilityUI(email) {
    const pill = document.getElementById("nav-eligibility-pill");
    const pillText = document.getElementById("nav-eligibility-text");
    const banner = document.getElementById("ineligible-warning-banner");
    const bannerEmail = document.getElementById("ineligible-user-email");
    const bannerReason = document.getElementById("ineligible-reason-text");

    const result = await checkIdentityEligibility(email);

    if (result.is_eligible_requester) {
        if (pill) {
            pill.className = "eligibility-pill eligible";
            pill.title = result.message;
        }
        if (pillText) pillText.innerText = result.domain ? `@${result.domain} (Verified)` : "Authorized Domain";
        if (banner) banner.style.display = "none";
    } else {
        if (pill) {
            pill.className = "eligibility-pill ineligible";
            pill.title = result.message;
        }
        if (pillText) pillText.innerText = "Ineligible Domain";
        if (banner) {
            banner.style.display = "flex";
            if (bannerEmail) bannerEmail.innerText = email;
            if (bannerReason) bannerReason.innerText = result.message;
        }
    }
}

function setCurrentUserEmail(email) {
    if (!email || !email.includes("@")) return;
    const cleanEmail = email.trim();
    localStorage.setItem("jit_user_email", cleanEmail);
    const badgeText = document.getElementById("current-user-text");
    if (badgeText) badgeText.innerText = cleanEmail;
    
    const requesterInput = document.getElementById("input-requester");
    if (requesterInput) requesterInput.value = cleanEmail;

    updateActiveUserEligibilityUI(cleanEmail);
    loadRequests();
}

async function promptSwitchUser() {
    const current = getCurrentUserEmail();
    const newUser = prompt(
        "Switch active GCP Identity:\nEnter your email (Authorized organization domains: @rwintrob.altostrat.com, @altostrat.com):",
        current
    );
    if (newUser && newUser.trim() !== "") {
        const cleanEmail = newUser.trim();
        const check = await checkIdentityEligibility(cleanEmail);
        if (!check.is_eligible_requester) {
            const proceed = confirm(
                `⚠️ Ineligible Identity Warning:\n\n"${cleanEmail}" does not belong to an authorized domain.\n\n${check.message}\n\nDo you want to switch to this identity for testing access rejection?`
            );
            if (!proceed) return;
        }
        setCurrentUserEmail(cleanEmail);
    }
}

function setRequesterEmail(email, btn) {
    const input = document.getElementById("input-requester");
    if (input) {
        input.value = email;
        checkFormEligibility();
    }
    if (btn && btn.parentElement) {
        btn.parentElement.querySelectorAll('.preset-chip').forEach(c => c.classList.remove('selected'));
        btn.classList.add('selected');
    }
}

function setApproverEmail(email, btn) {
    const input = document.getElementById("input-approver");
    if (input) {
        input.value = email;
        checkFormEligibility();
    }
    if (btn && btn.parentElement) {
        btn.parentElement.querySelectorAll('.preset-chip').forEach(c => c.classList.remove('selected'));
        btn.classList.add('selected');
    }
}

let eligibilityDebounceTimer = null;

async function checkFormEligibility() {
    clearTimeout(eligibilityDebounceTimer);
    eligibilityDebounceTimer = setTimeout(async () => {
        const requesterInput = document.getElementById("input-requester");
        const approverInput = document.getElementById("input-approver");
        const reqFeedback = document.getElementById("requester-eligibility-feedback");
        const apprFeedback = document.getElementById("approver-eligibility-feedback");
        const submitBtn = document.getElementById("btn-submit-request");

        if (!requesterInput || !approverInput) return;

        const reqEmail = requesterInput.value.trim();
        const apprEmail = approverInput.value.trim();

        let reqValid = false;
        let apprValid = false;

        if (reqEmail) {
            const check = await checkIdentityEligibility(reqEmail);
            if (check.is_eligible_requester) {
                reqValid = true;
                if (reqFeedback) {
                    reqFeedback.className = "eligibility-feedback feedback-eligible";
                    reqFeedback.innerHTML = `✓ Eligible Requester (@${escapeHtml(check.domain)})`;
                }
            } else {
                if (reqFeedback) {
                    reqFeedback.className = "eligibility-feedback feedback-ineligible";
                    reqFeedback.innerHTML = `✗ Ineligible: ${escapeHtml(check.message)}`;
                }
            }
        } else if (reqFeedback) {
            reqFeedback.innerHTML = "";
        }

        if (apprEmail) {
            const check = await checkIdentityEligibility(apprEmail);
            if (check.is_eligible_approver) {
                apprValid = true;
                if (apprFeedback) {
                    apprFeedback.className = "eligibility-feedback feedback-eligible";
                    apprFeedback.innerHTML = `✓ Eligible Approver (@${escapeHtml(check.domain)})`;
                }
            } else {
                if (apprFeedback) {
                    apprFeedback.className = "eligibility-feedback feedback-ineligible";
                    apprFeedback.innerHTML = `✗ Ineligible: ${escapeHtml(check.message)}`;
                }
            }
        } else if (apprFeedback) {
            apprFeedback.innerHTML = "";
        }

        if (reqEmail && apprEmail && reqEmail.toLowerCase() === apprEmail.toLowerCase()) {
            if (apprFeedback) {
                apprFeedback.className = "eligibility-feedback feedback-ineligible";
                apprFeedback.innerHTML = `✗ Separation of Duties violation: Approver cannot be the same as Requester`;
            }
            apprValid = false;
        }

        if (submitBtn) {
            submitBtn.disabled = !(reqValid && apprValid);
            if (submitBtn.disabled) {
                submitBtn.title = "Ensure requester and approver are valid and eligible organization identities.";
            } else {
                submitBtn.removeAttribute("title");
            }
        }
    }, 200);
}

let rolesCatalog = [];

async function loadRolesCatalog() {
    try {
        const res = await fetch("/api/roles");
        if (res.ok) {
            rolesCatalog = await res.json();
            populateRoleDropdown(rolesCatalog);
        }
    } catch (err) {
        console.warn("Could not fetch roles catalog:", err);
    }
}

function populateRoleDropdown(roles) {
    const roleSelect = document.getElementById("input-role");
    if (!roleSelect || !roles || roles.length === 0) return;

    let html = "";
    roles.forEach(role => {
        html += `<option value="${escapeHtml(role.role_id)}">${escapeHtml(role.title)} (${escapeHtml(role.role_id)})</option>`;
    });
    roleSelect.innerHTML = html;
    updateRoleDescriptionPreview();
}

function updateRoleDescriptionPreview() {
    const roleSelect = document.getElementById("input-role");
    const previewEl = document.getElementById("role-description-preview");
    if (!roleSelect || !previewEl) return;

    const selectedRoleId = roleSelect.value;
    const match = rolesCatalog.find(r => r.role_id === selectedRoleId);
    if (match && match.description) {
        previewEl.innerText = match.description;
    } else {
        previewEl.innerText = `Selected role: ${selectedRoleId}`;
    }
}

document.addEventListener("DOMContentLoaded", () => {
    // Initialize active user from localStorage if present
    const activeUser = getCurrentUserEmail();
    const badgeText = document.getElementById("current-user-text");
    if (badgeText) badgeText.innerText = activeUser;
    
    const requesterInput = document.getElementById("input-requester");
    if (requesterInput) requesterInput.value = activeUser;

    updateActiveUserEligibilityUI(activeUser);
    loadRolesCatalog();
    loadRequests();
    loadAuditLogs();
    
    // Auto-refresh data every 5 seconds
    setInterval(() => {
        loadRequests();
        loadAuditLogs();
    }, 5000);

    // Live countdown timer ticker every 1 second
    timerInterval = setInterval(updateCountdownTimers, 1000);
});

// Modal Toggles
function openRequestModal() {
    const requesterInput = document.getElementById("input-requester");
    if (requesterInput) requesterInput.value = getCurrentUserEmail();
    document.getElementById("request-modal").classList.add("active");
    checkFormEligibility();
}

function closeRequestModal() {
    document.getElementById("request-modal").classList.remove("active");
    document.getElementById("create-request-form").reset();
    const requesterInput = document.getElementById("input-requester");
    if (requesterInput) requesterInput.value = getCurrentUserEmail();
}

function openVerifyModal() {
    document.getElementById("verify-modal").classList.add("active");
}

function closeVerifyModal() {
    document.getElementById("verify-modal").classList.remove("active");
}


// Fetch Requests from REST API
async function loadRequests() {
    try {
        const response = await fetch("/api/requests", {
            headers: { "X-User-Email": getCurrentUserEmail() }
        });
        if (!response.ok) return;
        requestsData = await response.json();
        renderRequestsTable(requestsData);
        updateMetrics(requestsData);
    } catch (err) {
        console.error("Failed to load requests:", err);
    }
}

// Fetch Audit Logs from REST API
async function loadAuditLogs() {
    try {
        const response = await fetch("/api/audit", {
            headers: { "X-User-Email": getCurrentUserEmail() }
        });
        if (!response.ok) return;
        auditData = await response.json();
        renderAuditLogs(auditData);
    } catch (err) {
        console.error("Failed to load audit logs:", err);
    }
}

// Render Requests Data Table
function renderRequestsTable(requests) {
    const tbody = document.getElementById("requests-table-body");
    if (!tbody) return;
    if (!requests || requests.length === 0) {
        tbody.innerHTML = `<tr><td colspan="9" class="text-center py-4 text-muted">No JIT elevation requests found. Click "+ New Elevation Request" to create one.</td></tr>`;
        return;
    }

    let html = "";
    requests.forEach(req => {
        const statusBadge = getStatusBadge(req.status);
        const currentUser = getCurrentUserEmail();
        const isApprover = currentUser.toLowerCase() === req.approver_email.toLowerCase();

        let remainingTimeText = "-";
        if (req.status === "ACTIVE" && req.expires_at) {
            remainingTimeText = `<span class="timer-countdown" data-expires="${req.expires_at}">Calculating...</span>`;
        } else if (req.status === "EXPIRED" || req.status === "REVOKED") {
            remainingTimeText = `<span class="text-muted">Expired / Revoked</span>`;
        }

        // Action Buttons
        let actionButtons = "";
        if (req.status === "PENDING") {
            actionButtons = `
                <button class="btn btn-success btn-sm" onclick="handleApprove('${req.request_id}', true)">Approve</button>
                <button class="btn btn-danger btn-sm" onclick="handleApprove('${req.request_id}', false)">Reject</button>
            `;
        } else if (req.status === "ACTIVE") {
            actionButtons = `
                <button class="btn btn-danger btn-sm" onclick="handleRevoke('${req.request_id}')">Revoke Grant</button>
                <button class="btn btn-outline btn-sm" onclick="handleVerify('${req.request_id}')">Verify</button>
            `;
        } else {
            actionButtons = `
                <button class="btn btn-outline btn-sm" onclick="handleVerify('${req.request_id}')">Verify Proof</button>
            `;
        }

        // Verification Proof Indicator
        let verifyIndicator = "";
        if (req.verification_result && req.verification_result.verified_removed) {
            verifyIndicator = `<div class="verify-badge">✓ Verified Removed</div>`;
        }

        html += `
            <tr>
                <td><code>#${req.request_id}</code></td>
                <td>
                    <span class="clickable-link" onclick="filterByRequester('${escapeHtml(req.requester_email)}')" title="Click to filter audit logs by requester">
                        ${escapeHtml(req.requester_email)}
                    </span>
                </td>
                <td>
                    <span class="clickable-link" onclick="filterByProject('${escapeHtml(req.target_project_id)}')" title="Click to filter audit logs by project">
                        <strong>${escapeHtml(req.target_project_id)}</strong>
                    </span>
                </td>
                <td><code>${escapeHtml(req.role || 'roles/orgpolicy.policyAdmin')}</code></td>
                <td>
                    <span class="clickable-link" onclick="filterByApprover('${escapeHtml(req.approver_email)}')" title="Click to filter audit logs by approver">
                        ${escapeHtml(req.approver_email)}
                    </span>
                </td>
                <td title="${escapeHtml(req.justification)}">${truncateText(escapeHtml(req.justification), 30)}</td>
                <td>${statusBadge}</td>
                <td>${remainingTimeText}</td>
                <td>
                    <div style="display: flex; flex-direction: column; gap: 0.3rem;">
                        <div>${actionButtons}</div>
                        ${verifyIndicator}
                    </div>
                </td>
            </tr>
        `;
    });

    tbody.innerHTML = html;
    updateCountdownTimers();
}

// Countdown Timer logic
function updateCountdownTimers() {
    const timers = document.querySelectorAll(".timer-countdown");
    const now = new Date().getTime();

    timers.forEach(timer => {
        const expiresIso = timer.getAttribute("data-expires");
        if (!expiresIso) return;
        const expiresTime = new Date(expiresIso).getTime();
        const distance = expiresTime - now;

        if (distance < 0) {
            timer.innerHTML = `<span style="color: var(--rose-500); font-weight: bold;">Expired (Revoking...)</span>`;
        } else {
            const minutes = Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60));
            const seconds = Math.floor((distance % (1000 * 60)) / 1000);
            timer.innerHTML = `⏱️ <strong>${minutes}m ${seconds}s</strong>`;
        }
    });
}

// Render Dashboard Metrics Cards
function updateMetrics(requests) {
    let pending = 0;
    let active = 0;
    let verified = 0;

    requests.forEach(r => {
        if (r.status === "PENDING") pending++;
        if (r.status === "ACTIVE") active++;
        if (r.verification_result && r.verification_result.verified_removed) verified++;
    });

    const pendingEl = document.getElementById("stat-pending");
    const activeEl = document.getElementById("stat-active");
    const verifiedEl = document.getElementById("stat-verified");
    const totalEl = document.getElementById("stat-total");

    if (pendingEl) pendingEl.innerText = pending;
    if (activeEl) activeEl.innerText = active;
    if (verifiedEl) verifiedEl.innerText = verified;
    if (totalEl) totalEl.innerText = auditData.length;
}

// Focus & Highlight Audit Log Section
function focusAuditLogSection() {
    const section = document.getElementById("audit-section");
    if (section) {
        section.scrollIntoView({ behavior: "smooth", block: "start" });
        section.classList.remove("section-highlight-pulse");
        void section.offsetWidth; // trigger browser reflow
        section.classList.add("section-highlight-pulse");
        setTimeout(() => {
            section.classList.remove("section-highlight-pulse");
        }, 2000);
    }
}

// Switch Audit Log View Mode (Table vs Raw Stream)
function switchAuditView(viewMode) {
    const tableView = document.getElementById("audit-table-container");
    const streamView = document.getElementById("audit-log-container");
    const btnTable = document.getElementById("btn-view-table");
    const btnStream = document.getElementById("btn-view-stream");

    if (viewMode === "stream") {
        if (tableView) tableView.style.display = "none";
        if (streamView) streamView.style.display = "flex";
        if (btnTable) btnTable.classList.remove("active");
        if (btnStream) btnStream.classList.add("active");
    } else {
        if (tableView) tableView.style.display = "block";
        if (streamView) streamView.style.display = "none";
        if (btnTable) btnTable.classList.add("active");
        if (btnStream) btnStream.classList.remove("active");
    }
}

// Populate Dynamic Filter Dropdowns based on live data
function populateFilterDropdowns() {
    const requesters = new Set();
    const approvers = new Set();
    const projects = new Set();

    // Collect from audit entries
    auditData.forEach(entry => {
        if (entry.requester_email) requesters.add(entry.requester_email);
        else if (entry.event_type === "REQUEST_CREATED" && entry.actor_email && !entry.actor_email.startsWith("system:")) requesters.add(entry.actor_email);
        
        if (entry.approver_email) approvers.add(entry.approver_email);
        else if ((entry.event_type.includes("APPROV") || entry.event_type.includes("REJECT")) && entry.actor_email && !entry.actor_email.startsWith("system:")) approvers.add(entry.actor_email);
        
        if (entry.target_project_id) projects.add(entry.target_project_id);
    });

    // Collect from elevation requests
    requestsData.forEach(req => {
        if (req.requester_email) requesters.add(req.requester_email);
        if (req.approver_email) approvers.add(req.approver_email);
        if (req.actual_approver) approvers.add(req.actual_approver);
        if (req.target_project_id) projects.add(req.target_project_id);
    });

    updateSelectOptions("select-requester", Array.from(requesters).sort(), "All Requesters");
    updateSelectOptions("select-approver", Array.from(approvers).sort(), "All Approvers");
    updateSelectOptions("select-project", Array.from(projects).sort(), "All Projects");
}

function updateSelectOptions(selectId, items, defaultLabel) {
    const select = document.getElementById(selectId);
    if (!select) return;
    const currentVal = select.value;
    
    let html = `<option value="">${defaultLabel}</option>`;
    items.forEach(item => {
        const isSelected = item === currentVal ? "selected" : "";
        html += `<option value="${escapeHtml(item)}" ${isSelected}>${escapeHtml(item)}</option>`;
    });
    select.innerHTML = html;
}

// Handle Dropdown Selection Change
function onSelectFilterChange(filterType, value) {
    const inputMap = {
        requester: "filter-requester",
        approver: "filter-approver",
        project: "filter-project"
    };
    const inputId = inputMap[filterType];
    if (inputId) {
        const input = document.getElementById(inputId);
        if (input) input.value = value;
    }
    applyAuditFilters();
}

// Filter Action Helpers
function filterByRequester(email) {
    clearAuditFilters(false);
    const input = document.getElementById("filter-requester");
    const select = document.getElementById("select-requester");
    if (input) input.value = email;
    if (select) select.value = email;
    applyAuditFilters();
    focusAuditLogSection();
}

function filterByApprover(email) {
    clearAuditFilters(false);
    const input = document.getElementById("filter-approver");
    const select = document.getElementById("select-approver");
    if (input) input.value = email;
    if (select) select.value = email;
    applyAuditFilters();
    focusAuditLogSection();
}

function filterByProject(project) {
    clearAuditFilters(false);
    const input = document.getElementById("filter-project");
    const select = document.getElementById("select-project");
    if (input) input.value = project;
    if (select) select.value = project;
    applyAuditFilters();
    focusAuditLogSection();
}

function filterByRequestId(requestId) {
    clearAuditFilters(false);
    focusAuditLogSection();
    // Filter matching request ID
    renderFilteredAuditLogs(auditData.filter(l => l.request_id === requestId));
}

// Clear All Filters
function clearAuditFilters(shouldReapply = true) {
    const reqInput = document.getElementById("filter-requester");
    const reqSelect = document.getElementById("select-requester");
    const apprInput = document.getElementById("filter-approver");
    const apprSelect = document.getElementById("select-approver");
    const projInput = document.getElementById("filter-project");
    const projSelect = document.getElementById("select-project");
    const eventSelect = document.getElementById("filter-event-type");

    if (reqInput) reqInput.value = "";
    if (reqSelect) reqSelect.value = "";
    if (apprInput) apprInput.value = "";
    if (apprSelect) apprSelect.value = "";
    if (projInput) projInput.value = "";
    if (projSelect) projSelect.value = "";
    if (eventSelect) eventSelect.value = "ALL";

    if (shouldReapply) {
        applyAuditFilters();
    }
}

// Apply Filters to Audit Data
function applyAuditFilters() {
    const reqFilter = (document.getElementById("filter-requester")?.value || "").trim().toLowerCase();
    const apprFilter = (document.getElementById("filter-approver")?.value || "").trim().toLowerCase();
    const projFilter = (document.getElementById("filter-project")?.value || "").trim().toLowerCase();
    const eventTypeFilter = (document.getElementById("filter-event-type")?.value || "ALL").trim().toUpperCase();

    // Sync select dropdowns if exact match exists
    syncSelectDropdown("select-requester", reqFilter);
    syncSelectDropdown("select-approver", apprFilter);
    syncSelectDropdown("select-project", projFilter);

    // Filter logs
    const filtered = auditData.filter(entry => {
        // Requester Filter
        if (reqFilter) {
            const reqEmail = (entry.requester_email || (entry.event_type === "REQUEST_CREATED" ? entry.actor_email : "")).toLowerCase();
            if (!reqEmail.includes(reqFilter)) return false;
        }

        // Approver Filter
        if (apprFilter) {
            const apprEmail = (entry.approver_email || (entry.event_type.includes("APPROV") || entry.event_type.includes("REJECT") ? entry.actor_email : "")).toLowerCase();
            if (!apprEmail.includes(apprFilter)) return false;
        }

        // Project Filter
        if (projFilter) {
            const proj = (entry.target_project_id || "").toLowerCase();
            if (!proj.includes(projFilter)) return false;
        }

        // Event Type Filter
        if (eventTypeFilter !== "ALL") {
            if (entry.event_type.toUpperCase() !== eventTypeFilter) return false;
        }

        return true;
    });

    renderActiveFilterChips(reqFilter, apprFilter, projFilter, eventTypeFilter);
    renderFilteredAuditLogs(filtered);
}

function syncSelectDropdown(selectId, val) {
    const select = document.getElementById(selectId);
    if (!select) return;
    let found = false;
    for (let i = 0; i < select.options.length; i++) {
        if (select.options[i].value.toLowerCase() === val) {
            select.selectedIndex = i;
            found = true;
            break;
        }
    }
    if (!found && val === "") select.selectedIndex = 0;
}

// Render Active Filter Chips
function renderActiveFilterChips(reqFilter, apprFilter, projFilter, eventTypeFilter) {
    const chipsContainer = document.getElementById("active-filter-chips");
    if (!chipsContainer) return;

    let chipsHtml = "";
    if (reqFilter) {
        chipsHtml += `<span class="filter-chip">Requester: ${escapeHtml(reqFilter)} <span class="chip-remove" onclick="onSelectFilterChange('requester', '');">×</span></span>`;
    }
    if (apprFilter) {
        chipsHtml += `<span class="filter-chip">Approver: ${escapeHtml(apprFilter)} <span class="chip-remove" onclick="onSelectFilterChange('approver', '');">×</span></span>`;
    }
    if (projFilter) {
        chipsHtml += `<span class="filter-chip">Project: ${escapeHtml(projFilter)} <span class="chip-remove" onclick="onSelectFilterChange('project', '');">×</span></span>`;
    }
    if (eventTypeFilter && eventTypeFilter !== "ALL") {
        chipsHtml += `<span class="filter-chip">Event: ${escapeHtml(eventTypeFilter)} <span class="chip-remove" onclick="document.getElementById('filter-event-type').value='ALL'; applyAuditFilters();">×</span></span>`;
    }

    chipsContainer.innerHTML = chipsHtml;
}

// Render Cloud Audit Logs Container and Table
function renderAuditLogs(logs) {
    populateFilterDropdowns();
    applyAuditFilters();
}

// Render Filtered Audit Logs (Table & Raw Stream)
function renderFilteredAuditLogs(filteredLogs) {
    const totalCount = auditData.length;
    const filterCount = filteredLogs.length;

    const totalEl = document.getElementById("audit-total-count");
    const filterEl = document.getElementById("audit-filter-count");
    if (totalEl) totalEl.innerText = totalCount;
    if (filterEl) filterEl.innerText = filterCount;

    // 1. Render Structured Table
    const tbody = document.getElementById("audit-table-body");
    if (tbody) {
        if (!filteredLogs || filteredLogs.length === 0) {
            tbody.innerHTML = `<tr><td colspan="8" class="text-center py-4 text-muted">No audit events match the active filters.</td></tr>`;
        } else {
            let tableHtml = "";
            filteredLogs.forEach((log, index) => {
                const dateObj = new Date(log.timestamp);
                const formattedTime = dateObj.toLocaleDateString() + " " + dateObj.toLocaleTimeString();
                const eventBadge = getAuditEventBadge(log.event_type);
                
                const requester = log.requester_email || (log.event_type === "REQUEST_CREATED" ? log.actor_email : "-");
                const approver = log.approver_email || ((log.event_type.includes("APPROV") || log.event_type.includes("REJECT")) ? log.actor_email : "-");
                
                const payloadId = `payload-detail-${index}`;
                const payloadSummary = formatPayloadSummary(log.payload, log.event_type);
                const rawJson = escapeHtml(JSON.stringify(log.payload, null, 2));

                tableHtml += `
                    <tr>
                        <td class="whitespace-nowrap"><small class="text-muted">${formattedTime}</small></td>
                        <td>${eventBadge}</td>
                        <td>
                            <span class="clickable-link" onclick="filterByRequestId('${escapeHtml(log.request_id)}')" title="Filter events for request #${escapeHtml(log.request_id)}">
                                <code>#${escapeHtml(log.request_id)}</code>
                            </span>
                        </td>
                        <td>
                            <span class="clickable-link" onclick="filterByRequester('${escapeHtml(requester)}')" title="Filter by requester">
                                ${escapeHtml(requester)}
                            </span>
                        </td>
                        <td>
                            <span class="clickable-link" onclick="filterByApprover('${escapeHtml(approver)}')" title="Filter by approver">
                                ${escapeHtml(approver)}
                            </span>
                        </td>
                        <td>
                            <span class="clickable-link" onclick="filterByProject('${escapeHtml(log.target_project_id)}')" title="Filter by project">
                                <strong>${escapeHtml(log.target_project_id)}</strong>
                            </span>
                        </td>
                        <td><small class="actor-tag">${escapeHtml(log.actor_email)}</small></td>
                        <td>
                            <div class="payload-summary-box">
                                <div>${payloadSummary}</div>
                                <details class="payload-details">
                                    <summary class="payload-toggle">JSON</summary>
                                    <pre class="payload-raw-json">${rawJson}</pre>
                                </details>
                            </div>
                        </td>
                    </tr>
                `;
            });
            tbody.innerHTML = tableHtml;
        }
    }

    // 2. Render Raw Stream View
    const streamContainer = document.getElementById("audit-log-container");
    if (streamContainer) {
        if (!filteredLogs || filteredLogs.length === 0) {
            streamContainer.innerHTML = `<div class="log-entry log-info">No audit logs matching current filter parameters.</div>`;
        } else {
            let streamHtml = "";
            filteredLogs.forEach(log => {
                const ts = new Date(log.timestamp).toLocaleTimeString();
                streamHtml += `<div class="log-entry">[${ts}] <strong>${log.event_type}</strong> | Requester: ${log.requester_email || 'N/A'} | Approver: ${log.approver_email || 'N/A'} | Project: ${log.target_project_id} | Actor: ${log.actor_email} | ${JSON.stringify(log.payload)}</div>`;
            });
            streamContainer.innerHTML = streamHtml;
        }
    }
}

// Get Formatted Event Type Badge
function getAuditEventBadge(eventType) {
    switch (eventType) {
        case "REQUEST_CREATED":
            return `<span class="badge badge-info">📝 REQUEST_CREATED</span>`;
        case "GRANT_ACTIVE":
            return `<span class="badge badge-active">🛡️ GRANT_ACTIVE</span>`;
        case "GRANT_MANUALLY_REVOKED":
            return `<span class="badge badge-revoked">⏹️ MANUAL_REVOKE</span>`;
        case "GRANT_EXPIRED_REVOKED":
            return `<span class="badge badge-expired">⏱️ AUTO_REVOKE</span>`;
        case "VERIFICATION_COMPLETED":
            return `<span class="badge badge-verified">🔍 VERIFIED_ABSENT</span>`;
        case "REQUEST_REJECTED":
            return `<span class="badge badge-rejected">❌ REJECTED</span>`;
        default:
            return `<span class="badge">${escapeHtml(eventType)}</span>`;
    }
}

// Format Payload Summary Context
function formatPayloadSummary(payload, eventType) {
    if (!payload || Object.keys(payload).length === 0) return `<span class="text-muted">None</span>`;
    
    let parts = [];
    if (payload.justification) {
        parts.push(`<span>Justification: "${truncateText(escapeHtml(payload.justification), 35)}"</span>`);
    }
    if (payload.duration_minutes) {
        parts.push(`<span>Duration: ${payload.duration_minutes}m</span>`);
    }
    if (payload.comments) {
        parts.push(`<span>Comments: "${truncateText(escapeHtml(payload.comments), 30)}"</span>`);
    }
    if (payload.revocation_message) {
        parts.push(`<span>Message: ${escapeHtml(payload.revocation_message)}</span>`);
    }
    if (payload.verification && payload.verification.verified_removed !== undefined) {
        const icon = payload.verification.verified_removed ? "✓ Verified Clean" : "❌ Removal Pending";
        parts.push(`<span>${icon}</span>`);
    }
    if (payload.policy_etag) {
        parts.push(`<span>ETag: <code>${escapeHtml(payload.policy_etag)}</code></span>`);
    }

    return parts.length > 0 ? parts.join(" &bull; ") : `<span class="text-muted">Detailed payload</span>`;
}


// Form Submission: Create Elevation Request
async function handleCreateRequest(event) {
    event.preventDefault();
    const requester = document.getElementById("input-requester").value.trim();
    const targetProject = document.getElementById("input-target-project").value.trim();
    const roleSelect = document.getElementById("input-role");
    const role = roleSelect ? roleSelect.value.trim() : "roles/orgpolicy.policyAdmin";
    const duration = parseInt(document.getElementById("input-duration").value);
    const approver = document.getElementById("input-approver").value.trim();
    const justification = document.getElementById("input-justification").value.trim();

    if (requester.toLowerCase() === approver.toLowerCase()) {
        alert("Separation of Duties Policy: Requester cannot be their own designated approver.");
        return;
    }

    try {
        const response = await fetch("/api/requests", {
            method: "POST",
            headers: { 
                "Content-Type": "application/json",
                "X-User-Email": requester 
            },
            body: JSON.stringify({
                requester_email: requester,
                target_project_id: targetProject,
                role: role,
                duration_minutes: duration,
                approver_email: approver,
                justification: justification
            })
        });

        if (!response.ok) {
            const errData = await response.json();
            alert("Error creating request: " + (errData.detail || "Unknown error"));
            return;
        }

        closeRequestModal();
        await loadRequests();
        await loadAuditLogs();
    } catch (err) {
        alert("Failed to submit request: " + err);
    }
}

// Handle Approve / Reject
async function handleApprove(requestId, isApproved) {
    const comments = isApproved ? "Approved via JIT Portal" : "Rejected via JIT Portal";
    const currentUser = getCurrentUserEmail();

    try {
        const response = await fetch(`/api/requests/${requestId}/approve`, {
            method: "POST",
            headers: { 
                "Content-Type": "application/json",
                "X-User-Email": currentUser
            },
            body: JSON.stringify({
                approver_email: currentUser,
                approved: isApproved,
                comments: comments
            })
        });

        if (!response.ok) {
            const errData = await response.json();
            alert("Approval Failed: " + (errData.detail || "Unknown error"));
            return;
        }

        await loadRequests();
        await loadAuditLogs();
    } catch (err) {
        alert("Action failed: " + err);
    }
}

// Handle Manual Revoke
async function handleRevoke(requestId) {
    if (!confirm("Are you sure you want to manually revoke this active JIT grant immediately?")) return;

    try {
        const response = await fetch(`/api/requests/${requestId}/revoke`, { 
            method: "POST",
            headers: { "X-User-Email": getCurrentUserEmail() }
        });
        if (!response.ok) {
            const errData = await response.json();
            alert("Revocation Failed: " + (errData.detail || "Unknown error"));
            return;
        }

        await loadRequests();
        await loadAuditLogs();
    } catch (err) {
        alert("Revocation failed: " + err);
    }
}

// Handle Verification Check
async function handleVerify(requestId) {
    const modalBody = document.getElementById("verify-modal-body");
    modalBody.innerHTML = `<div class="text-center py-4">Querying GCP Resource Manager API for Project IAM Policy...</div>`;
    openVerifyModal();

    try {
        const response = await fetch(`/api/requests/${requestId}/verify`, {
            headers: { "X-User-Email": getCurrentUserEmail() }
        });
        const vResult = await response.json();

        const req = allRequestsCache.find(r => r.request_id === requestId);
        const roleDisplay = req ? req.role : "roles/orgpolicy.policyAdmin";

        let statusClass = vResult.verified_removed ? "alert-info" : "alert-danger";
        let statusBadge = vResult.verified_removed 
            ? `<span style="color: var(--emerald-500); font-weight: bold;">✓ VERIFIED ABSENT</span>`
            : `<span style="color: var(--rose-500); font-weight: bold;">❌ PERMISSION STILL PRESENT</span>`;

        modalBody.innerHTML = `
            <div class="alert ${statusClass}">
                <h4>Status: ${statusBadge}</h4>
                <p style="margin-top: 0.5rem;">${escapeHtml(vResult.details)}</p>
            </div>
            <div style="margin-top: 1rem; font-size: 0.85rem;">
                <p><strong>Verification Timestamp:</strong> ${new Date(vResult.timestamp).toLocaleString()}</p>
                <p><strong>IAM Policy ETag:</strong> <code>${vResult.policy_etag || "N/A"}</code></p>
                <p><strong>Audited Role:</strong> <code>${escapeHtml(roleDisplay)}</code></p>
            </div>
        `;

        await loadRequests();
        await loadAuditLogs();
    } catch (err) {
        modalBody.innerHTML = `<div class="alert alert-danger">Failed to verify permission removal: ${err}</div>`;
    }
}

// Utility Functions
function getStatusBadge(status) {
    switch (status) {
        case "PENDING": return `<span class="badge badge-pending">PENDING</span>`;
        case "ACTIVE": return `<span class="badge badge-active">ACTIVE</span>`;
        case "REVOKED": return `<span class="badge badge-revoked">REVOKED</span>`;
        case "EXPIRED": return `<span class="badge badge-expired">EXPIRED</span>`;
        case "REJECTED": return `<span class="badge badge-rejected">REJECTED</span>`;
        default: return `<span class="badge">${status}</span>`;
    }
}

function truncateText(str, length) {
    if (!str) return "";
    return str.length > length ? str.substring(0, length) + "..." : str;
}

function escapeHtml(str) {
    if (!str) return "";
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}
