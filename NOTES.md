# Notes

## Future Production Integration Question — Blocking

**Question:** If Abuse Engine only alerts but doesn't block, is it useful to companies?

**Short answer:** Alerting-only is a real limitation for commercial adoption. The solution is to keep detection log-only and delegate enforcement to the customer's existing infrastructure.

### Three approaches (in order of integration cost)

**1. WAF rule injection** — Abuse Engine detects from logs → automatically pushes a block rule to the customer's existing WAF (AWS WAF, Cloudflare, nginx deny directive). Detection stays log-only, no new infrastructure. Latency to block: 5–30s (detection time + rule push). Acceptable for persistent attacks, not flash attacks.

**2. Blocklist sidecar (recommended for product)** — Abuse Engine maintains a Redis-backed blocklist. A small gateway plugin (nginx module, Kong plugin, AWS Lambda authorizer) does a single Redis lookup per request — binary, sub-1ms. Once Abuse Engine's detection fires it writes to Redis; all subsequent requests from that IP/key are blocked synchronously by the plugin, not Abuse Engine. This is how Signal Sciences (Fastly) and similar products work. Detection is async and smart; enforcement is a dumb fast lookup.

**3. Inline reverse proxy** — Abuse Engine sits in the request path. Unknown IPs pass through while analysis runs in parallel. Once flagged, blocks immediately. Adds real latency (~50–100ms rule-only, ~500ms LLM path) before a threat is confirmed; zero latency afterwards. Highest integration cost — requires rerouting all traffic.

### Implications for the paper
"Zero-integration detection" remains accurate and is still the novel research claim — detection requires no code changes. Blocking via WAF rule injection (option 1) reuses existing customer infrastructure and doesn't contradict the zero-integration claim. Option 2 requires one small plugin deployment but is still far lighter than an inline proxy.

### Decision deferred to product phase
The research prototype validates detection quality. Blocking mechanism design (which option, which gateway plugins) is a product-phase decision after the paper is published.

### Tier Pricing That Actually Gets Early Adopters In
Pilot (Early Adopter) — ₹0 for 60 days, then ₹3,999/month
Detection only, your first 5 clients, you do the onboarding manually, weekly check-in call included. This is how you learn what clients actually care about.
Starter — ₹4,999/month (~$60)
Detection + rules push blocking (AWS WAF/Cloudflare), weekly email report, up to 10M API calls/month. This is your actual entry product.
Growth — ₹14,999/month (~$180)
Everything in Starter + middleware SDK blocking, Slack alerts, up to 50M calls/month, priority support.
Pro — ₹29,999/month (~$360)
Everything in Growth + custom thresholds, quarterly business review, up to 200M calls/month.

Great set of questions, all connected. Let me take them in order.

---

## The Vercel-to-Enterprise Transition

The moment a customer shifts from self-serve to enterprise isn't a product change, it's a relationship change. Here's what triggers it:

They've been on Starter for 2-3 months. Your dashboard is showing consistent detection numbers. Their engineering team references the tool in internal discussions. Then one of three things happens:

They hit a limit (API call volume, need custom thresholds, need Slack alerts their team is already asking for). You reach out proactively before they ask. Or a security incident happens elsewhere in the news and their CTO suddenly wants a proper vendor relationship not just a tool they signed up for on a website.

That's when you send this:

"You've been running Abuse Engine for 90 days. You've had X abuse attempts flagged, estimated exposure prevented ₹Y. I'd love to get on a 30 minute call to talk about what a longer term setup looks like for your scale."

That call is where it becomes a business conversation. You discuss their growth plans, their API volume trajectory, what blocking capabilities they need. You propose an annual contract with a 10-15% discount over monthly. You send a proper agreement instead of a dashboard subscription.

The product doesn't change dramatically. The relationship formality does. They go from "we use this tool" to "we have a vendor contract with Abuse Engine."

---

## What Stops Them Building It Themselves

This is called the build vs buy problem and it's one of the most common objections in B2B SaaS. The honest answer has layers.

**Short term:** Building an internal detection system requires an engineer to scope it, build it, maintain it, and update it as abuse patterns evolve. Even a basic version is 3-6 weeks of a senior engineer's time. At ₹80,000-1,50,000/month engineer cost that's ₹2-9 lakh just to build v1. Your Starter plan is ₹4,999/month. The math is obvious.

**Medium term:** Abuse patterns change constantly. Attackers adapt. Your system improves because you're seeing patterns across multiple clients simultaneously. Their internal tool sees only their own traffic. Your multi-tenant data advantage compounds over time. This is your actual moat, not the technology itself.

**Long term:** Maintenance. Security tooling that isn't actively maintained becomes a liability. Nobody wants to own that internally at a 50-person startup where engineers are building product features.

The build vs buy answer you give a CTO is simply: "You could build this. A senior engineer would take 4-6 weeks minimum, then someone owns maintenance forever. We're ₹4,999/month and we're monitoring abuse patterns across multiple companies simultaneously so our detection improves faster than any internal tool could."

The companies that build internally are the ones that grow to 500+ engineers and have a dedicated security team. That's not your ICP.

---

## What Stops Them Going to a Well Known Service

The well known services (Salt Security, Traceable, Noname) have three problems for your ICP:

Their pricing starts at $2,000-5,000/month minimum, often higher. They're built for US enterprise procurement cycles which take months. They have no India presence, no India pricing, no India support timezone.

A Series A Indian SaaS company cannot justify $3,000/month for security tooling when their entire infra spend might be $5,000/month. You are the option that exists for them. That's not a small thing.

The risk is AWS and Cloudflare themselves building native abuse detection into their products, which they're slowly doing. That's a bigger long term threat than niche security vendors. Keep that in mind as you build, your differentiation needs to be the multi-signal intelligence layer not just "detects abuse on your API."

---

## How Do You Know It'll Actually Return ROI Before You Have Data

Honestly you don't know for certain yet and you shouldn't pretend to. But you can make a credible directional claim without lying.

The approach that works at zero-customer stage is industry benchmarks not your own data. Real numbers that exist publicly:

- Gartner estimates API attacks cost companies an average of $44,000 per incident
- Cloudflare's 2023 report showed 17% of all internet traffic is malicious bots targeting APIs
- A company doing 10 million API calls/month with even 5% abuse rate is processing 500,000 malicious requests, each consuming compute

You use these numbers to construct a plausible estimate for their specific situation during the free trial conversation. "Based on industry averages, a company at your API volume typically sees X% abuse. At your compute costs that's roughly ₹Y/month in wasted resources. We'll show you your actual number within 30 days."

You're not claiming ROI. You're claiming you'll show them their own data and let them decide. That's honest and it's a low enough bar that most CTOs will say yes.

Once your first 2-3 pilots generate real numbers, you replace the industry benchmarks with your own case studies. "Client A at similar scale saw ₹87,000/month in prevented abuse exposure. Their Starter plan is ₹4,999." That's when the sales motion becomes significantly easier.

---

## The "Twice the Money" Style Claim

"We'll save you twice what you pay us" is a classic ROI guarantee and it works when you can actually prove it. Some SaaS companies offer it as a formal money-back guarantee. The problem at your stage is you can't guarantee it because you don't control what abuse they're actually experiencing.

What you can say honestly and effectively instead:

"If after 30 days the dashboard isn't showing you at least 10x your monthly cost in prevented exposure, cancel and pay nothing."

10x sounds aggressive but API abuse at scale almost always justifies it because compute costs are real and fraud exposure is real. If a company is genuinely not seeing 10x ROI it probably means their abuse problem is small, which means they probably weren't the right customer anyway.

This framing does two things: it signals confidence in the product, and it pre-qualifies customers. A CTO who's worried about ROI at ₹4,999/month probably doesn't have a serious enough abuse problem to be your customer yet.

---

## The Sequencing You've Identified is Correct

Free monitoring first, blocking after commitment, is exactly right and here's the structural reason why:

Monitoring is read-only. You're just watching their logs. Zero risk to their production system. Any CTO can approve this in 5 minutes.

Blocking touches production. WAF rules, middleware, inline proxy all have the potential to cause a false positive that breaks a legitimate API call. That's a production incident risk. No CTO approves that from a vendor they've known for 10 days.

By the time they've seen 60-90 days of accurate detection with low false positives, the blocking conversation is easy. "You've seen us flag X requests, our false positive rate has been Y%, want us to start blocking automatically?" They already trust the detection, blocking is just the next logical step.

The trust has to be earned before you touch production. Your sequencing understands that intuitively.