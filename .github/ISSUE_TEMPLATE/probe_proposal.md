---
name: Probe proposal
about: Propose a new probe for DQIX
title: '[PROBE] '
labels: probe
assignees: ''
---

**Probe name**
A short, descriptive name for the probe (e.g., `tls`, `dnssec`).

**What does this probe check?**
A clear description of what security/governance aspect this probe will assess.

**Why is this important?**
Explain why this check is valuable for domain quality assessment.

**Proposed scoring criteria**
Describe how the probe should score domains (0.0 to 1.0):
- What conditions would result in a perfect score (1.0)?
- What conditions would result in a zero score (0.0)?
- Are there intermediate scores? How are they calculated?

**Example implementation**
```python
from dqix.probes.base import Probe

class MyProbe(Probe):
    name = "my_probe"
    description = "What this probe checks"

    def run(self, domain: str) -> float:
        # Implementation details
        return 1.0
```

**Preset weights**
Which compliance level(s) should include this probe? What weight do you suggest?
- Level 1 (Minimal): [weight or N/A]
- Level 2 (Safe): [weight or N/A]
- Level 3 (Policy): [weight or N/A]

**Additional context**
Add any other context about the probe proposal here. 