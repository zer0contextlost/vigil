# Vigil Dashboard UI Specification

**Document Version:** 1.0  
**Date:** 2026-05-03  
**Status:** Implementation-Ready  
**Target:** Single-binary Rust app with embedded HTML/CSS/JS assets

---

## 1. Executive Summary

This specification defines the complete visual design and interaction model for vigil's web dashboard—a live runtime observability tool for AI coding agents. The dashboard presents three core views (Sessions List, Session Detail, Write Approval Banner) in a dark, developer-friendly interface optimized for fast event scanning and decision-making.

The design uses a single, self-contained CSS file (no external CDN links) and vanilla JavaScript with minimal Alpine.js helpers. The dashboard consumes events via Server-Sent Events (SSE) and auto-updates in real time.

---

## 2. Color Palette

All colors are dark-theme optimized for long viewing sessions.

### Semantic Colors (Established)
These match vigil's existing report HTML:
- **Success Green:** `#22c55e`
- **Warning Amber:** `#f59e0b`
- **Error Red:** `#ef4444`
- **Neutral Gray:** `#6b7280`

### Dark Theme Base Colors
- **Background (Page):** `#0f1419` (near-black, high contrast for long sessions)
- **Surface (Cards/Panels):** `#1a1f2e` (elevated from background)
- **Surface Hover:** `#232d3f` (slightly brighter on hover/focus)
- **Border Primary:** `#3a4557` (visible dividers)
- **Border Secondary:** `#2a3142` (subtle separators)

### Text Colors
- **Primary Text:** `#e5e7eb` (off-white, readable on dark background)
- **Secondary Text:** `#9ca3af` (muted for metadata, timestamps)
- **Muted Text:** `#6b7280` (for disabled/inactive states)
- **Code/Monospace:** `#c7d4e8` (slightly blue-tinted for terminal aesthetics)

### Status & Alert Badges
- **BURN (cost alert):** `#ef4444` red background, `#fff` text
- **DRFT (drift):** `#f59e0b` amber background, `#000` text
- **PINJ (prompt injection):** `#ef4444` red background, `#fff` text
- **LOOP (tool loop):** `#f59e0b` amber background, `#000` text
- **PIII (PII):** `#ef4444` red background, `#fff` text
- **EXFL (exfil):** `#ef4444` red background, `#fff` text
- **LIVE (session status):** `#22c55e` green background, `#000` text
- **COMPLETED:** `#6b7280` gray background, `#e5e7eb` text

### Write Risk Level Colors
- **Low Risk:** `#22c55e` green
- **Medium Risk:** `#f59e0b` amber
- **High Risk:** `#ef4444` red

---

## 3. Typography

### Font Stack
```css
--font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", "Helvetica Neue", sans-serif;
--font-mono: "Menlo", "Monaco", "Courier New", monospace;
```

Rationale: System fonts work offline, render crisp on Windows/Linux/macOS, no CDN required.

### Type Scale
- **XL Heading (page title):** 28px, 600 weight, letter-spacing -0.5px
- **L Heading (view sections):** 20px, 600 weight, letter-spacing -0.25px
- **M Heading (subsections):** 16px, 600 weight
- **Body Text:** 14px, 400 weight, line-height 1.5
- **Small Text (metadata):** 13px, 400 weight, color `#9ca3af`
- **Tiny Text (timestamps):** 12px, 400 weight, color `#6b7280`
- **Code/Monospace:** 12px, 400 weight, line-height 1.4, `--font-mono`

---

## 4. Overall Layout Architecture

### Page Structure
```
┌─────────────────────────────────────────────────────────────┐
│ [Vigil Logo/Title]  [Session Selector ▼]  [Settings ⚙]     │  ← Header (fixed, 60px)
├─────────────────────────────────────────────────────────────┤
│ [WRITE APPROVAL BANNER — if pending write]                  │  ← Approval banner (if active)
├──────────────┬──────────────────────────────────────────────┤
│              │                                               │
│ Sessions     │  [MAIN VIEW AREA]                            │  ← Main content (flex row)
│ List         │  Sessions List -or- Session Detail           │
│ (sidebar)    │                                               │
│              │                                               │
│ (200px)      │ (remaining width, scrollable)                │
│              │                                               │
└──────────────┴──────────────────────────────────────────────┘
```

### Key Design Decisions
1. **Fixed header** with title and session switcher — allows quick jumping between sessions
2. **Left sidebar with sessions list** — persistent, 200px fixed width, scrollable
3. **Main content area** — flex-grow to fill remaining space, two alternate views (list or detail)
4. **Write approval banner** — floats at top of main area when a write is pending, dismisses on approval/rejection
5. **No top navbar clutter** — Settings are minimalist (gear icon), focus is on content

### Responsive Behavior
- **Desktop (≥1200px):** Full layout as described above
- **Tablet (768px–1199px):** Sidebar collapses to 60px icon-only strip; main view expands
- **Mobile (<768px):** Sidebar hides entirely (hamburger toggle); main view takes full width

For MVP, optimize for desktop/laptop. Mobile responsiveness is nice-to-have.

---

## 5. Sessions List View (Sidebar + Table)

### Sidebar (Left, 200px)

**Header:**
```
┌────────────────────┐
│ Vigil 0.6.0        │  ← Session title/version, 16px, 600 weight
│ ────────────────── │  ← border-bottom: 1px `#3a4557`
│ [+ New Session]    │  ← Button, green, 12px padding, hover effect
└────────────────────┘
```

**Session List Container:**
- Scrollable div, overflow-y auto, height = viewport - 140px
- Each session is a card with:
  - **Session name** (adjective-noun, 13px 600 weight)
  - **Model** (12px secondary text, e.g., "claude-opus")
  - **Status badge** (LIVE/COMPLETED, 2px px padding, 11px font)
  - **Cost so far** (13px, green if under budget, red if over)
  - **Last event time** (12px muted, relative time: "2m ago")

**Session Card Styling:**
```css
.session-card {
  padding: 12px;
  margin-bottom: 8px;
  background: #1a1f2e;
  border-left: 3px solid transparent;
  border-radius: 4px;
  cursor: pointer;
  transition: all 200ms ease;
}

.session-card:hover {
  background: #232d3f;
  border-left-color: #3b82f6;
}

.session-card.active {
  background: #232d3f;
  border-left-color: #22c55e;
}
```

**Card Indicator:** Thick left border (3px) changes color on hover (blue) and when active (green).

---

### Main Sessions List View (Center/Right)

**Table Layout:**

```
┌─────────────────────────────────────────────────────────────────────────┐
│ All Sessions (12 live, 48 completed)                                    │
├─────────────────────────────────────────────────────────────────────────┤
│ Agent        │ Model     │ Cost  │ $/min │ Last Event           │ Alerts  │ Time    │ Status    │
├─────────────────────────────────────────────────────────────────────────┤
│ Claude Code  │ opus      │ 0.42  │ 0.08  │ Read symlink...      │ 🔴BURN  │ 2m ago  │ LIVE  ⏱  │
│ Cursor       │ gpt-4o    │ 1.20  │ 0.15  │ Write complete       │ 🟡DRFT  │ 5s ago  │ LIVE  ⏱  │
│ IDE Gemini   │ flash     │ 0.08  │ 0.02  │ Session finished     │ none    │ 23m ago │ CMPL     │
└─────────────────────────────────────────────────────────────────────────┘
```

**Column Specs:**

| Column | Width | Type | Details |
|--------|-------|------|---------|
| Agent | 120px | text | AI agent name (Claude Code, Cursor, etc.) |
| Model | 100px | text | LLM model (opus, gpt-4o, flash), monospace |
| Cost | 70px | number | USD total, right-aligned, green/red |
| $/min | 70px | number | Burn rate, right-aligned, red if >threshold |
| Last Event | 180px | text | Truncated event description, primary text |
| Alerts | 140px | badges | Space for up to 3 alert badges (BURN, DRFT, PINJ, etc.) |
| Time | 80px | time | Relative time ago or absolute if >1hr |
| Status | 90px | badge | LIVE or COMPLETED; LIVE has spinning indicator |

**Table Row Behavior:**
1. **Hover:** Entire row background → `#232d3f`, left border → blue (`#3b82f6`)
2. **Click:** Navigates to Session Detail view for that session
3. **Live update:** Every SSE event updates the Cost, $/min, Last Event, and Alerts columns in real-time (no flash, smooth transition)
4. **Live rows pin to top:** Sessions with status=LIVE appear above COMPLETED sessions; within each group, sort by most-recent first
5. **Status indicator:** LIVE sessions show a small pulsing green dot next to status badge

**Table Styling:**

```css
.sessions-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 14px;
}

.sessions-table thead th {
  padding: 12px 8px;
  text-align: left;
  background: #232d3f;
  border-bottom: 2px solid #3a4557;
  font-weight: 600;
  color: #e5e7eb;
  position: sticky;
  top: 0;
}

.sessions-table tbody tr {
  border-bottom: 1px solid #2a3142;
  transition: background-color 200ms ease;
}

.sessions-table tbody tr:hover {
  background-color: #232d3f;
}

.sessions-table td {
  padding: 10px 8px;
  color: #e5e7eb;
}

.sessions-table td.number {
  text-align: right;
  color: #c7d4e8;
  font-family: var(--font-mono);
}
```

**Last Event Truncation:** If the event description is >50 chars, truncate with ellipsis and show full text in a tooltip on hover.

---

## 6. Session Detail View

**Navigation:** Click a session row in the list → detail view replaces the table. Breadcrumb at top: `Sessions > [Session Name] (frozen-raven) · claude-opus · $0.42`

**Layout:**

```
┌──────────────────────────────────────────────────────────────┐
│ ← Back | frozen-raven (claude-opus) · $0.42 · 12 turns       │ ← Header bar
├──────────────────────────────────────────────────────────────┤
│ Started: 2026-05-03 14:25:18 | Duration: 4m 32s | Cost: ... │ ← Info strip
├──────────────────────────────────────────────────────────────┤
│ EVENT TIMELINE (scrollable)                                  │
│ ┌────────────────────────────────────────────────────────┐   │
│ │ [Turn 1] LLM Request (4,521 in)           14:25:18     │ ◄ ─ Click to expand
│ │   ▶ Claude Opus                          2026-05-03   │   │
│ │                                                        │   │
│ │ [Turn 1] Tool: Read — /src/main.rs       14:25:20     │   │
│ │   ▶ Success: 247 bytes                   +0.02s       │   │
│ │                                                        │   │
│ │ [Turn 1] ALERT: BURN — $0.12/min         14:25:21     │   │ Red bg
│ │   ▶ Cost climbing fast                                │   │
│ │                                                        │   │
│ │ [Turn 1] LLM Response (1,240 out)        14:25:35     │   │
│ │   ▶ $0.08 (cache hit 10%)                            │   │
│ │                                                        │   │
│ │ [Turn 2] LLM Request (4,892 in)          14:25:36     │   │
│ │   ▶ Claude Opus + cache                              │   │
│ │                                                        │   │
│ │ [Turn 2] File Write: PENDING APPROVAL    14:25:42     │   │ Yellow bg
│ │   ▶ /src/index.ts (Medium Risk)                      │   │
│ │   ▶ [Show] [Approve] [Reject]                         │   │
│ │                                                        │   │
│ │ ... (scroll down for more events) ...                │   │
│ └────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────┘
```

### Info Strip (Below Breadcrumb)
```css
.detail-info-strip {
  display: flex;
  gap: 20px;
  padding: 12px 16px;
  background: #232d3f;
  border-bottom: 1px solid #3a4557;
  font-size: 13px;
  color: #9ca3af;
}

.detail-info-strip strong {
  color: #e5e7eb;
}
```

Contents: `Started: [timestamp] | Duration: [h]m[s] | Cost: $[x.xx] | Turns: [n] | Status: [LIVE/COMPLETED]`

### Event Timeline

**Container:**
```css
.timeline {
  flex: 1;
  overflow-y: auto;
  overflow-x: hidden;
  padding: 16px 0;
  background: #0f1419;
}

.timeline-item {
  padding: 12px 16px;
  border-left: 3px solid transparent;
  border-bottom: 1px solid #2a3142;
  transition: all 200ms ease;
  cursor: pointer;
}

.timeline-item:hover {
  background: #1a1f2e;
  border-left-color: #3b82f6;
}

.timeline-item.expanded {
  background: #1a1f2e;
}
```

**Event Row Structure (Collapsed):**

Each event row is a collapsible `<details>` element styled to look like a table row:

```html
<details class="timeline-item">
  <summary class="timeline-summary">
    <span class="turn-badge">[Turn 1]</span>
    <span class="event-type">LLM Request</span>
    <span class="event-detail">4,521 input tokens</span>
    <span class="timeline-time">14:25:18</span>
  </summary>
  <div class="timeline-content">
    <!-- Expanded details go here -->
  </div>
</details>
```

**Summary Styling:**

```css
.timeline-summary {
  display: flex;
  align-items: center;
  gap: 12px;
  font-size: 14px;
  user-select: none;
  list-style: none; /* Hide default <details> triangle */
}

.timeline-summary::-webkit-details-marker {
  display: none; /* Hide Safari details marker */
}

.timeline-summary::before {
  content: "▶";
  width: 16px;
  text-align: center;
  color: #9ca3af;
  transition: transform 200ms ease;
  font-size: 11px;
}

.timeline-item[open] .timeline-summary::before {
  transform: rotate(90deg);
}

.turn-badge {
  background: #3a4557;
  padding: 2px 6px;
  border-radius: 3px;
  font-size: 12px;
  color: #c7d4e8;
  font-weight: 600;
  min-width: 60px;
}

.event-type {
  font-weight: 600;
  color: #e5e7eb;
  min-width: 100px;
}

.event-detail {
  flex: 1;
  color: #9ca3af;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.timeline-time {
  color: #6b7280;
  font-family: var(--font-mono);
  font-size: 12px;
  margin-left: 20px;
}
```

**Event Type Styling (by event kind):**

```css
.timeline-item.llm-request { border-left-color: #3b82f6; }
.timeline-item.llm-response { border-left-color: #8b5cf6; }
.timeline-item.tool-call { border-left-color: #06b6d4; }
.timeline-item.tool-result { border-left-color: #10b981; }
.timeline-item.alert { border-left-color: #ef4444; background: rgba(239, 68, 68, 0.05); }
.timeline-item.write-approval { border-left-color: #f59e0b; background: rgba(245, 158, 11, 0.05); }
.timeline-item.pii-detection { border-left-color: #ef4444; }
.timeline-item.file-write { border-left-color: #22c55e; }
.timeline-item.file-read { border-left-color: #8b5cf6; }
```

### Expanded Event Details

**LLM Request (Expanded):**

```
▼ [Turn 1] LLM Request — 4,521 input tokens                   14:25:18
  
  Provider:    Anthropic
  Model:       claude-3-opus-20250219
  Turn:        1
  
  Input Tokens:    4,521
  System Prompt:   [System prompt loaded from CLAUDE.md (2,340 bytes)]
  User Message:    [Show] (Click to expand, displays raw message)
  
  Request sent at: 2026-05-03T14:25:18.234Z
```

```css
.timeline-content {
  padding: 12px 16px 12px 32px;
  background: rgba(58, 69, 87, 0.2);
  border-radius: 0 0 4px 4px;
  margin-top: 0;
  font-size: 13px;
  line-height: 1.6;
}

.timeline-content dl {
  display: grid;
  grid-template-columns: 140px 1fr;
  gap: 10px;
  margin: 0;
}

.timeline-content dt {
  color: #9ca3af;
  font-weight: 600;
}

.timeline-content dd {
  margin: 0;
  color: #e5e7eb;
  font-family: var(--font-mono);
}

.timeline-content dd.expandable {
  cursor: pointer;
  color: #3b82f6;
  text-decoration: underline;
}
```

**LLM Response (Expanded):**

```
▼ [Turn 1] LLM Response — 1,240 output tokens                 14:25:35
  
  Cost:              $0.0847
  Output Tokens:     1,240
  Cache Read:        512 tokens (10% cache hit)
  Cache Write:       0 tokens
  Duration:          ~17s
  Finish Reason:     end_turn
  
  Response Preview:  [First 200 chars of response text...]
                     [Show Full] [Copy]
```

**Tool Call (Expanded):**

```
▼ [Turn 1] Tool: Read — /src/main.rs                          14:25:20
  
  Tool:       Read
  Input:      { "file_path": "/src/main.rs" }
  Tool ID:    toolu_01ARZ3NDEKTSV4RRFFQ69G5FAV
  Duration:   ~2.1s
  
  Result:     [Success] 247 bytes read (8 lines)
              [Show Content] [Copy]
```

**Tool Result (Expanded, Error Case):**

```
▼ [Turn 1] Tool: Bash — rm -rf /                              14:26:05
  
  Tool:       Bash (DENIED)
  Input:      { "command": "rm -rf /" }
  Duration:   ~0.3s
  
  Result:     ❌ ERROR: Tool execution was denied by policy
              Reason: Destructive command blocked
              Policy Rule: filesystem.dangerous-patterns
```

**Alert (Expanded):**

```
▼ [Turn 1] ALERT: BURN RATE — $0.12/min                       14:25:21
  
  Alert Type:    Burn Rate
  Severity:      HIGH (red)
  Threshold:     $0.10/min
  Current Rate:  $0.12/min
  
  Detail:        LLM costs are accelerating. Session cost is now $0.42 in 3.5 minutes.
                 Consider: compacting context, switching to a cheaper model, or pausing.
  
  Action:        [Set new threshold] [Pause session] [Dismiss]
```

**Write Approval (Expanded, Pending):**

```
▼ [Turn 2] File Write: PENDING APPROVAL                        14:25:42
  
  Action:        File Write (PENDING YOUR DECISION)
  Path:          /src/index.ts
  Risk Level:    🟡 MEDIUM
  
  Change:        Modified 28 lines, added 15, removed 13
  
  [Show Diff (split view)]  [Approve ✓]  [Reject ✗]
```

**Write Approval (Expanded, Approved):**

```
▼ [Turn 2] File Write: APPROVED                               14:25:45
  
  Path:          /src/index.ts
  Risk Level:    🟡 MEDIUM
  Status:        ✓ APPROVED at 14:25:45
  
  Change:        Modified 28 lines, added 15, removed 13
```

### Timeline Live Tail Behavior

**Auto-scroll rules:**
- If user is scrolled to the **bottom** of the timeline → new events auto-append and scroll view down
- If user **scrolls up** (away from bottom) → lock scroll position, don't auto-scroll; new events append silently
- Visual indicator: If scroll is locked, show a **"New events. Scroll down to see"** pill at bottom right (sticky, blue)
- Clicking the pill auto-scrolls to bottom and resumes auto-scroll

```css
.timeline-notice {
  position: fixed;
  bottom: 20px;
  right: 20px;
  background: #3b82f6;
  color: white;
  padding: 8px 12px;
  border-radius: 4px;
  font-size: 12px;
  cursor: pointer;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
}

.timeline-notice:hover {
  background: #2563eb;
}
```

### Code/Diff Display

When expanding a message, request body, or diff, render code with **inline syntax highlighting** (no external library — use simple CSS classes for JavaScript, Python, YAML, JSON, Bash):

```css
.code-block {
  background: rgba(0, 0, 0, 0.3);
  border: 1px solid #3a4557;
  border-radius: 4px;
  padding: 8px 12px;
  font-family: var(--font-mono);
  font-size: 12px;
  line-height: 1.4;
  overflow-x: auto;
  color: #c7d4e8;
}

.code-block .kw { color: #a78bfa; } /* Keywords */
.code-block .str { color: #34d399; } /* Strings */
.code-block .num { color: #fbbf24; } /* Numbers */
.code-block .cmt { color: #6b7280; } /* Comments */
.code-block .fn { color: #60a5fa; } /* Functions */
```

---

## 7. Write Approval Banner

**Positioning:** Fixed at the top of the main content area (below header, above session detail or list).

**Visibility:** Only appears when `event.type == "FileWrite" && approval_status == "PENDING"`

**Layout:**

```
┌─────────────────────────────────────────────────────────────────────────┐
│ ⚠ FILE WRITE PENDING YOUR APPROVAL                                      │
├─────────────────────────────────────────────────────────────────────────┤
│ Path:      /src/index.ts                                                │
│ Risk:      🟡 MEDIUM (modified existing file, 15 new lines)            │
│                                                                         │
│ Before (3 lines):                 After (5 lines):                      │
│ ───────────────────────────────   ──────────────────────────────        │
│ const config = {                  const config = {                      │
│   apiUrl: 'http://localhost:3000' │   apiUrl: process.env.API_URL,      │
│ }                                 │   timeout: 30000,                    │
│                                   │   retries: 3                         │
│                                   │ }                                    │
│                                                                         │
│  [Full Diff]  [Approve ✓]  [Reject ✗]  [Timeout: 30s]                 │
└─────────────────────────────────────────────────────────────────────────┘
```

**Structure:**

```css
.write-approval-banner {
  position: fixed;
  top: 60px; /* Below fixed header */
  left: 0;
  right: 0;
  z-index: 100;
  background: linear-gradient(to bottom, rgba(245, 158, 11, 0.1), rgba(245, 158, 11, 0.05));
  border-bottom: 2px solid #f59e0b;
  padding: 16px 24px;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
  animation: slideDown 300ms ease-out;
}

@keyframes slideDown {
  from {
    transform: translateY(-100%);
    opacity: 0;
  }
  to {
    transform: translateY(0);
    opacity: 1;
  }
}

.approval-header {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 12px;
  font-weight: 600;
  color: #f59e0b;
}

.approval-meta {
  display: grid;
  grid-template-columns: auto 1fr;
  gap: 12px 20px;
  margin-bottom: 12px;
  font-size: 13px;
}

.approval-meta dt {
  color: #9ca3af;
  font-weight: 600;
}

.approval-meta dd {
  margin: 0;
  color: #e5e7eb;
}

.approval-risk-low { color: #22c55e; }
.approval-risk-medium { color: #f59e0b; }
.approval-risk-high { color: #ef4444; }
```

**Diff Display (Split View):**

```css
.approval-diff {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
  margin: 12px 0;
  font-size: 12px;
  border: 1px solid #3a4557;
  border-radius: 4px;
  background: rgba(0, 0, 0, 0.2);
  padding: 12px;
}

.approval-diff-side {
  overflow-x: auto;
}

.approval-diff-side h4 {
  margin: 0 0 8px 0;
  color: #9ca3af;
  font-weight: 600;
}

.approval-diff-line {
  font-family: var(--font-mono);
  line-height: 1.4;
  padding: 2px 4px;
  white-space: pre-wrap;
  word-break: break-word;
}

.approval-diff-line.add { color: #34d399; background: rgba(52, 211, 153, 0.05); }
.approval-diff-line.remove { color: #f87171; background: rgba(248, 113, 113, 0.05); }
```

**Buttons:**

```css
.approval-button {
  padding: 8px 16px;
  margin-right: 8px;
  border: none;
  border-radius: 4px;
  font-size: 13px;
  font-weight: 600;
  cursor: pointer;
  transition: all 200ms ease;
}

.approval-button-approve {
  background: #22c55e;
  color: #000;
}

.approval-button-approve:hover {
  background: #16a34a;
}

.approval-button-reject {
  background: #ef4444;
  color: #fff;
}

.approval-button-reject:hover {
  background: #dc2626;
}

.approval-button-dismiss {
  background: transparent;
  color: #9ca3af;
  border: 1px solid #3a4557;
}

.approval-button-dismiss:hover {
  background: #232d3f;
  color: #e5e7eb;
}

.approval-timer {
  display: inline-block;
  margin-left: 20px;
  font-size: 12px;
  color: #6b7280;
}

.approval-timer.warning {
  color: #f59e0b;
  font-weight: 600;
}
```

**Timeout Behavior:**
- Approval request has a 30-second timeout (configurable)
- Countdown displayed in banner: "Timeout: 30s" → "Timeout: 2s" (updates each second)
- At 10s remaining, text turns amber
- At 0s: banner auto-dismisses (auto-rejection or manual dismissal per policy config)

**Dismissal:**
- After approve/reject, banner slides out in 300ms (reverse of slideDown), then removed from DOM
- If user clicks elsewhere (or navigates to different session), banner stays but disables buttons

---

## 8. Component Library

### Alert Badges

Used in Sessions List and Timeline events.

```html
<span class="alert-badge alert-burn">BURN</span>
<span class="alert-badge alert-drft">DRFT</span>
<span class="alert-badge alert-pinj">PINJ</span>
<span class="alert-badge alert-loop">LOOP</span>
<span class="alert-badge alert-piii">PIII</span>
<span class="alert-badge alert-exfl">EXFL</span>
```

```css
.alert-badge {
  display: inline-block;
  padding: 3px 8px;
  border-radius: 3px;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.5px;
  white-space: nowrap;
}

.alert-burn { background: #ef4444; color: #fff; }
.alert-drft { background: #f59e0b; color: #000; }
.alert-pinj { background: #ef4444; color: #fff; }
.alert-loop { background: #f59e0b; color: #000; }
.alert-piii { background: #ef4444; color: #fff; }
.alert-exfl { background: #ef4444; color: #fff; }
```

### Status Badges

```html
<span class="status-badge status-live">LIVE</span>
<span class="status-badge status-completed">COMPLETED</span>
```

```css
.status-badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 4px 10px;
  border-radius: 3px;
  font-size: 12px;
  font-weight: 600;
}

.status-live {
  background: #22c55e;
  color: #000;
}

.status-live::before {
  content: "";
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: #000;
  animation: pulse 2s infinite;
}

@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.3; }
}

.status-completed {
  background: #6b7280;
  color: #e5e7eb;
}
```

### Risk Level Badge (Write Approvals)

```html
<span class="risk-badge risk-low">Low</span>
<span class="risk-badge risk-medium">Medium</span>
<span class="risk-badge risk-high">High</span>
```

```css
.risk-badge {
  display: inline-block;
  padding: 3px 8px;
  border-radius: 3px;
  font-size: 12px;
  font-weight: 600;
}

.risk-low { background: rgba(34, 197, 94, 0.2); color: #22c55e; border: 1px solid #22c55e; }
.risk-medium { background: rgba(245, 158, 11, 0.2); color: #f59e0b; border: 1px solid #f59e0b; }
.risk-high { background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid #ef4444; }
```

### Buttons

**Primary (Approve):**
```css
.btn-primary {
  background: #22c55e;
  color: #000;
  border: none;
  padding: 8px 16px;
  border-radius: 4px;
  font-weight: 600;
  cursor: pointer;
  transition: background 200ms ease;
}

.btn-primary:hover {
  background: #16a34a;
}

.btn-primary:active {
  transform: scale(0.98);
}
```

**Danger (Reject):**
```css
.btn-danger {
  background: #ef4444;
  color: #fff;
  border: none;
  padding: 8px 16px;
  border-radius: 4px;
  font-weight: 600;
  cursor: pointer;
  transition: background 200ms ease;
}

.btn-danger:hover {
  background: #dc2626;
}

.btn-danger:active {
  transform: scale(0.98);
}
```

**Secondary (Dismiss, Back, etc.):**
```css
.btn-secondary {
  background: transparent;
  color: #9ca3af;
  border: 1px solid #3a4557;
  padding: 8px 16px;
  border-radius: 4px;
  font-weight: 600;
  cursor: pointer;
  transition: all 200ms ease;
}

.btn-secondary:hover {
  background: #232d3f;
  color: #e5e7eb;
  border-color: #4a5568;
}

.btn-secondary:active {
  transform: scale(0.98);
}
```

### Skeleton Loaders (for loading states)

Used when waiting for session list to load or events to stream in.

```html
<div class="skeleton skeleton-text" style="width: 60%;"></div>
<div class="skeleton skeleton-table-row"></div>
```

```css
.skeleton {
  background: linear-gradient(
    90deg,
    #1a1f2e 0%,
    #232d3f 50%,
    #1a1f2e 100%
  );
  background-size: 200% 100%;
  animation: shimmer 1.5s infinite;
}

@keyframes shimmer {
  0% { background-position: 200% 0; }
  100% { background-position: -200% 0; }
}

.skeleton-text {
  height: 14px;
  border-radius: 3px;
  margin-bottom: 8px;
}

.skeleton-table-row {
  height: 40px;
  border-radius: 4px;
  margin-bottom: 8px;
}
```

---

## 9. Interaction Patterns

### SSE Event Streaming

**Connection Management:**
- On page load, establish SSE connection to `/api/events/stream`
- Include `session_id` query param if in Session Detail view
- Endpoint streams `text/event-stream` with newline-delimited JSON objects
- Each line is a single event JSON: `{ "type": "LlmRequest", "timestamp": "...", ... }`

**Event Handling JavaScript:**

```javascript
let eventSource = new EventSource(`/api/events/stream?session_id=${sessionId}`);

eventSource.addEventListener('message', (e) => {
  const event = JSON.parse(e.data);
  
  // Route to handler based on event.type
  switch (event.type) {
    case 'LlmRequest':
      handleLlmRequest(event);
      break;
    case 'LlmResponse':
      handleLlmResponse(event);
      break;
    case 'ToolCall':
      handleToolCall(event);
      break;
    case 'ToolCallResult':
      handleToolResult(event);
      break;
    case 'FileWrite':
      handleFileWrite(event);
      break;
    case 'Alert':
      handleAlert(event);
      break;
    // ... etc
  }
});

eventSource.addEventListener('error', (e) => {
  if (e.readyState === EventSource.CLOSED) {
    // Reconnect after 3 seconds
    setTimeout(() => reconnect(), 3000);
  }
});
```

**Reconnection:** On SSE disconnect, show a small banner at bottom: "Connection lost. Reconnecting…" and attempt to reconnect with exponential backoff (3s, 6s, 12s, 30s).

### Sessions List Real-Time Updates

**Update Strategy (No Full Re-render):**
- When SSE delivers an event for a session already in the list:
  1. Find the session row by session_id
  2. Update only the changed cells: Cost, $/min, Last Event, Alerts
  3. Use CSS transitions for smooth value changes
  4. Don't flash the entire row

**Example (JavaScript with CSS transitions):**

```javascript
function updateSessionRow(sessionId, eventData) {
  const row = document.querySelector(`[data-session-id="${sessionId}"]`);
  if (!row) return;
  
  const costCell = row.querySelector('.cost-cell');
  const rateCell = row.querySelector('.rate-cell');
  const eventCell = row.querySelector('.event-cell');
  const alertsCell = row.querySelector('.alerts-cell');
  
  // Fade out the cell
  costCell.style.opacity = '0.5';
  
  // Update content
  costCell.textContent = `$${eventData.totalCost.toFixed(2)}`;
  
  // Fade back in
  setTimeout(() => {
    costCell.style.opacity = '1';
  }, 50);
}
```

### Session Detail Live Tail

**Auto-scroll Logic:**

```javascript
const timeline = document.querySelector('.timeline');

function isScrolledToBottom() {
  const threshold = 50; // pixels
  return (
    timeline.scrollHeight - timeline.scrollTop - timeline.clientHeight < threshold
  );
}

function addTimelineEvent(eventHtml) {
  const wasAtBottom = isScrolledToBottom();
  
  const eventEl = document.createElement('div');
  eventEl.innerHTML = eventHtml;
  timeline.appendChild(eventEl);
  
  if (wasAtBottom) {
    timeline.scrollTop = timeline.scrollHeight;
  } else {
    showScrollNotice(); // Show "New events. Scroll down to see" pill
  }
}

timeline.addEventListener('scroll', () => {
  if (isScrolledToBottom()) {
    hideScrollNotice();
  }
});

function showScrollNotice() {
  let notice = document.querySelector('.timeline-notice');
  if (!notice) {
    notice = document.createElement('div');
    notice.className = 'timeline-notice';
    notice.textContent = 'New events. Scroll down to see.';
    notice.onclick = () => {
      timeline.scrollTop = timeline.scrollHeight;
      notice.remove();
    };
    document.body.appendChild(notice);
  }
}

function hideScrollNotice() {
  const notice = document.querySelector('.timeline-notice');
  if (notice) notice.remove();
}
```

### Write Approval Flow

**Approve Button Click:**
```javascript
document.querySelector('.approval-button-approve').onclick = async () => {
  const writeId = document.querySelector('.write-approval-banner').dataset.writeId;
  
  const response = await fetch('/api/write-approval', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ write_id: writeId, approved: true })
  });
  
  if (response.ok) {
    // Banner slides out, SSE delivers WriteApprovalDecision event
    // which updates the timeline
    dismissBanner();
  } else {
    showErrorToast('Failed to approve write');
  }
};
```

### Error States

**SSE Reconnection Failure (after 3 retries):**
Show a red banner at top: "Unable to connect to vigil. Refresh the page to retry."

**Empty States:**

Sessions List when no sessions:
```
┌──────────────────────────────────────────────┐
│                                              │
│         No sessions yet                      │
│                                              │
│    Start an AI agent with vigil enabled.     │
│                                              │
│    [Documentation] [Settings]                │
│                                              │
└──────────────────────────────────────────────┘
```

Session Detail when first loading (before events arrive):
```
┌──────────────────────────────────────────────┐
│ Loading session events...                    │
│ ▁▂▃▄▅▆▇█ (progress bar or skeleton loaders)  │
└──────────────────────────────────────────────┘
```

---

## 10. CSS Architecture

### File Structure
Single file: `assets/dashboard.css` (embedded via `rust-embed`)

### CSS Custom Properties (Design Tokens)

```css
:root {
  /* Colors */
  --color-bg-page: #0f1419;
  --color-bg-surface: #1a1f2e;
  --color-bg-surface-hover: #232d3f;
  
  --color-border-primary: #3a4557;
  --color-border-secondary: #2a3142;
  
  --color-text-primary: #e5e7eb;
  --color-text-secondary: #9ca3af;
  --color-text-muted: #6b7280;
  --color-text-code: #c7d4e8;
  
  /* Semantic colors */
  --color-success: #22c55e;
  --color-warning: #f59e0b;
  --color-danger: #ef4444;
  --color-info: #3b82f6;
  --color-accent: #8b5cf6;
  
  /* Typography */
  --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", "Helvetica Neue", sans-serif;
  --font-mono: "Menlo", "Monaco", "Courier New", monospace;
  
  --font-size-xs: 12px;
  --font-size-sm: 13px;
  --font-size-base: 14px;
  --font-size-lg: 16px;
  --font-size-xl: 20px;
  --font-size-2xl: 28px;
  
  --font-weight-normal: 400;
  --font-weight-semibold: 600;
  --font-weight-bold: 700;
  
  /* Spacing */
  --spacing-xs: 4px;
  --spacing-sm: 8px;
  --spacing-md: 12px;
  --spacing-lg: 16px;
  --spacing-xl: 20px;
  --spacing-2xl: 24px;
  
  /* Borders & shadows */
  --border-radius-sm: 3px;
  --border-radius-md: 4px;
  --border-radius-lg: 8px;
  
  --shadow-sm: 0 1px 2px rgba(0, 0, 0, 0.05);
  --shadow-md: 0 2px 8px rgba(0, 0, 0, 0.1);
  --shadow-lg: 0 4px 12px rgba(0, 0, 0, 0.2);
  
  /* Transitions */
  --transition-fast: 200ms ease;
  --transition-base: 300ms ease;
  --transition-slow: 500ms ease;
}
```

### Organization

```css
/* ========== RESET & BASE ========== */
* { margin: 0; padding: 0; box-sizing: border-box; }
body { ... }
input, button, textarea { ... }

/* ========== LAYOUT ========== */
.container { ... }
.header { ... }
.sidebar { ... }
.main { ... }

/* ========== TYPOGRAPHY ========== */
h1, h2, h3 { ... }
.heading-xl { ... }
.text-primary { ... }
.text-secondary { ... }

/* ========== COMPONENTS ========== */
.btn { ... }
.btn-primary { ... }
.badge { ... }
.alert-badge { ... }
/* ... etc ... */

/* ========== VIEWS ========== */
.sessions-list { ... }
.sessions-table { ... }
.session-detail { ... }
.timeline { ... }

/* ========== ANIMATIONS ========== */
@keyframes pulse { ... }
@keyframes slideDown { ... }

/* ========== MEDIA QUERIES ========== */
@media (max-width: 768px) { ... }

/* ========== PRINT ========== */
@media print { ... }
```

### Responsive Breakpoints

```css
/* Desktop: ≥1200px (default styles above) */

/* Tablet: 768px to 1199px */
@media (max-width: 1199px) {
  .sidebar {
    width: 60px; /* Icon-only mode */
  }
  .sidebar .session-name {
    display: none; /* Hide text */
  }
  .main {
    flex: 1;
  }
}

/* Mobile: <768px */
@media (max-width: 767px) {
  .sidebar {
    display: none; /* Hide entirely, show hamburger instead */
  }
  .header {
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  .hamburger-btn {
    display: block;
  }
  .main {
    width: 100%;
  }
  .sessions-table {
    font-size: 12px; /* Smaller on mobile */
  }
  .sessions-table td, th {
    padding: 6px 4px;
  }
}
```

### No External Dependencies

All CSS is vanilla. No Tailwind, no CSS-in-JS libraries, no external fonts. The monospace font rendering will be slightly different on Windows (Courier New fallback) vs macOS/Linux (Menlo default), but this is acceptable.

---

## 11. HTML/JS Architecture

### HTML Structure (High Level)

```html
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Vigil Dashboard</title>
  <link rel="stylesheet" href="dashboard.css">
</head>
<body>
  <header class="header">
    <div class="header-left">
      <h1 class="logo">vigil</h1>
    </div>
    <div class="header-center">
      <select id="session-selector" class="session-selector">
        <!-- Options populated by JS -->
      </select>
    </div>
    <div class="header-right">
      <button class="btn-settings" title="Settings">⚙</button>
    </div>
  </header>

  <div id="write-approval-banner" class="write-approval-banner hidden">
    <!-- Populated by JS when write approval event arrives -->
  </div>

  <div class="page-container">
    <aside class="sidebar" id="sidebar">
      <div class="sidebar-header">
        <h2>Sessions</h2>
        <button class="btn btn-primary btn-sm">+ New</button>
      </div>
      <div id="sessions-list" class="sessions-list">
        <!-- Sessions populated by JS -->
      </div>
    </aside>

    <main class="main" id="main">
      <!-- Sessions List view or Session Detail view, populated by JS -->
    </main>
  </div>

  <script src="dashboard.js"></script>
</body>
</html>
```

### JavaScript Structure

**Modules (vanilla, no build system required):**

```javascript
// dashboard.js — main entry point

class VigilDashboard {
  constructor() {
    this.currentSessionId = null;
    this.sessions = new Map();
    this.eventSource = null;
  }
  
  async init() {
    await this.loadSessions();
    this.setupEventStream();
    this.renderSessionsList();
  }
  
  async loadSessions() {
    // GET /api/sessions → populate this.sessions Map
  }
  
  setupEventStream() {
    // new EventSource('/api/events/stream')
    // Wire up message handlers
  }
  
  renderSessionsList() {
    // Render sessions to sidebar + main table
  }
  
  showSessionDetail(sessionId) {
    this.currentSessionId = sessionId;
    // Render Session Detail view
  }
  
  handleTimelineEvent(event) {
    // Route event to appropriate handler
  }
  
  handleFileWrite(event) {
    // Show write approval banner
  }
}

const dashboard = new VigilDashboard();
dashboard.init();
```

**No frameworks.** Alpine.js is fine if you want to use `x-show`, `x-data` for local state, but not required. Keep it simple.

---

## 12. API Endpoints (Expected)

These endpoints are called by the frontend:

```
GET /api/sessions
  Response: [{ id, agent, model, cost, started_at, status, name }, ...]

GET /api/sessions/:session_id
  Response: { id, agent, model, events: [...], started_at, ended_at, ... }

GET /api/events/stream[?session_id=...]
  Response: Server-Sent Events (text/event-stream)
  Format: { "type": "LlmRequest", "timestamp": "...", ... }

POST /api/write-approval
  Body: { write_id: string, approved: boolean }
  Response: { ok: true }

GET /api/settings
  Response: { auto_approve: bool, timeout_secs: number, ... }

POST /api/settings
  Body: { auto_approve: bool, timeout_secs: number, ... }
  Response: { ok: true }
```

These are expected by the frontend. Implementation in the Rust backend is outside scope of this spec.

---

## 13. Loading & Error States

### Page Load Sequence

1. **Blank page with header** (0ms) — static HTML only
2. **Skeleton loaders appear** (100ms) — async JS fetches /api/sessions
3. **Sessions list populated** (200ms) — rendered from JSON response
4. **SSE connection opens** (250ms) — eventSource listener attached
5. **Events start flowing** (300ms+) — live updates to table/timeline

### Connection Error Handling

**SSE Disconnect:**
- Banner appears at bottom: "Connection lost. Reconnecting…"
- Auto-retry after 3s, 6s, 12s, 30s (exponential backoff)
- On successful reconnect, banner disappears
- If max retries exceeded (after ~60s), show: "Connection could not be established. Manual refresh required."

**API Error:**
- If /api/sessions fails: "Unable to load sessions. Check your connection and refresh."
- If /api/write-approval fails: Toast at bottom right: "Failed to approve write. Try again."

### Offline Behavior

vigil is a local tool. If the user kills the Rust daemon, the page stales out. No fancy offline caching — just show a connection error banner.

---

## 14. Accessibility

While vigil is a developer tool (not required to meet WCAG Level AA), basic a11y is good practice:

- **Color contrast:** All text meets 4.5:1 for normal text, 3:1 for large text.
- **Keyboard navigation:** Tab through buttons, Enter to activate, arrow keys in select dropdowns.
- **Focus indicators:** `:focus-visible` outlines on all interactive elements (blue, 2px).
- **Alt text:** Not critical for this tool (no images except SVG timeline), but code blocks should be copyable.
- **Labels:** All inputs have associated `<label>` elements or `aria-label` attributes.

Example:
```css
button:focus-visible, input:focus-visible, select:focus-visible {
  outline: 2px solid #3b82f6;
  outline-offset: 2px;
}
```

---

## 15. Performance Considerations

### Timeline Virtual Scrolling (Optional Optimization)

If a session has 10,000+ events, rendering all DOM nodes will lag. Implement virtual scrolling:

```javascript
class VirtualTimeline {
  constructor(container, itemHeight) {
    this.container = container;
    this.itemHeight = itemHeight;
    this.visibleRange = null;
    this.allEvents = [];
  }
  
  addEvent(event) {
    this.allEvents.push(event);
    this.render();
  }
  
  render() {
    // Calculate visible range based on scroll position
    const scrollTop = this.container.scrollTop;
    const visibleCount = Math.ceil(this.container.clientHeight / this.itemHeight);
    const startIndex = Math.floor(scrollTop / this.itemHeight);
    const endIndex = startIndex + visibleCount + 10; // Buffer
    
    // Render only events in range
    const toRender = this.allEvents.slice(startIndex, endIndex);
    // ... update DOM ...
  }
}
```

This is optional for MVP. Add it if sessions routinely exceed 1,000 events.

### CSS Transitions Over JS Animations

Use CSS transitions for smooth updates (better performance):

```css
.cost-cell {
  transition: opacity var(--transition-fast);
}
```

Avoid `setInterval` for real-time updates; SSE events are driven by the server.

---

## 16. Future Extensibility

### Planned Features (Out of Scope for MVP)

1. **Session Filters** — filter by model, status, cost range, agent
2. **Export Session** — download as JSON, HTML report, or CSV
3. **Replay Session** — mock upstream, re-run with fake data
4. **Policy Editor** — inline policy rule editing (visual builder)
5. **Dark/Light theme toggle** — persist in localStorage
6. **Notifications** — browser push when high-severity alerts fire

### Design for Extensibility

- **CSS custom properties** — easy to theme later
- **Modular JS classes** — each view is its own class, easy to extend
- **Data-driven rendering** — events are plain JSON, no tight coupling to HTML structure
- **Semantic HTML** — no divitis, uses `<details>`, `<summary>`, `<table>` properly

---

## 17. Testing Checklist

Before shipping:

- [ ] Sessions list loads and displays 5+ sessions
- [ ] Clicking a session row opens detail view
- [ ] SSE events arrive and update the table in real time (no flashing)
- [ ] Write approval banner appears, shows diff, buttons work
- [ ] Auto-scroll in timeline works (scrolls to bottom when at bottom, locks when scrolled up)
- [ ] Click event rows to expand/collapse
- [ ] Links in event details are copyable/selectable
- [ ] Settings dropdown works
- [ ] Mobile layout (hamburger sidebar) works on iPad/phone
- [ ] SSE reconnection works (kill server, restart, events resume)
- [ ] Browser console has no errors
- [ ] Page works in Chrome, Firefox, Safari (Windows, Linux, macOS preferred)

---

## 18. File Manifest

**Assets to create/embed in binary:**

```
assets/
  ├── dashboard.html     ← Entry page (skeleton + script tags)
  ├── dashboard.css      ← All styles, single file
  ├── dashboard.js       ← All JavaScript, single file, no imports
  └── favicon.ico        ← Optional: Vigil icon (16x16)
```

**Rust code to embed:**

```rust
// in vigil-proxy or main binary
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "assets/"]
pub struct Dashboard;
```

---

## 19. Example DOM Snippet (Sessions List Row)

```html
<tr class="sessions-table-row" data-session-id="550e8400-e29b-41d4-a716-446655440000">
  <td class="agent">Claude Code</td>
  <td class="model">claude-opus</td>
  <td class="cost number">$0.42</td>
  <td class="rate number">$0.08</td>
  <td class="event">Read /src/index.ts…</td>
  <td class="alerts">
    <span class="alert-badge alert-burn">BURN</span>
  </td>
  <td class="time">2m ago</td>
  <td class="status">
    <span class="status-badge status-live">LIVE <span class="pulse"></span></span>
  </td>
</tr>
```

---

## 20. Design System Summary

| Element | Style | Rationale |
|---------|-------|-----------|
| **Background** | Very dark (`#0f1419`) | Reduces eye strain, developer preference |
| **Surfaces** | Slightly elevated (`#1a1f2e`) | Clear hierarchy, readable |
| **Borders** | Subtle gray (`#3a4557`) | Not harsh, guides attention |
| **Text** | Off-white (`#e5e7eb`) | High contrast, readable for long sessions |
| **Code** | Blue-tinted mono (`#c7d4e8`) | Visual distinction from prose |
| **Success** | Green (`#22c55e`) | Matches existing vigil report |
| **Warning** | Amber (`#f59e0b`) | High visibility, not as urgent as red |
| **Error** | Red (`#ef4444`) | Immediate attention |
| **Transitions** | 200ms cubic-bezier | Smooth, not distracting |
| **Typography** | System fonts | Fast, offline, crisp on all platforms |
| **Sidebar** | Fixed width | Always-visible context |
| **Main area** | Flex-grow | Scalable to any screen size |

---

## 21. Conclusion

This specification is **complete and implementation-ready**. A developer can build the HTML/CSS/JS directly from this document without design ambiguity or back-and-forth questions.

**Key deliverables:**
1. Self-contained CSS (one file, no CDN)
2. Vanilla JS (no frameworks, no build step)
3. SSE-driven real-time updates
4. Three clear views (Sessions List, Session Detail, Write Approval Banner)
5. Dark theme optimized for developer use
6. Mobile-responsive (best-effort, desktop-first)
7. Zero external dependencies

All hex colors, spacing, typography, component styles, and interaction patterns are defined. Ready to code.

---

**Document prepared:** 2026-05-03  
**Status:** ✓ Ready for implementation
