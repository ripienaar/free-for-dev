# free-for.dev

Developers and Open Source authors now have many services offering free tiers, but finding them all takes time to make informed decisions.

This is a list of software (SaaS, PaaS, IaaS, etc.) and other offerings with free developer tiers.

The scope of this particular list is limited to things that infrastructure developers (System Administrator, DevOps Practitioners, etc.) are likely to find useful. We love all the free services out there, but it would be good to keep it on topic. It's a grey line sometimes, so this is opinionated; please don't feel offended if I don't accept your contribution.

This list results from Pull Requests, reviews, ideas, and work done by 1600+ people. You can also help by sending [Pull Requests](https://github.com/ripienaar/free-for-dev) to add more services or remove ones whose offerings have changed or been retired.

[![Track Awesome List](https://www.trackawesomelist.com/badge.svg)](https://www.trackawesomelist.com/ripienaar/free-for-dev)

**NOTE**: This list is only for as-a-Service offerings, not for self-hosted software. To be eligible, a service must offer a free tier, not just a free trial. The free tier must be for at least a year if it is time-bucketed. We also consider the free tier from a security perspective, so SSO is fine, but I will not accept services that restrict TLS to paid-only tiers.

# Table of Contents

  * [Major Cloud Providers' Always-Free Limits](#major-cloud-providers)
  * [Cloud management solutions](#cloud-management-solutions)
  * [Analytics, Events, and Statistics](#analytics-events-and-statistics)
  * [APIs, Data and ML](#apis-data-and-ml)
  * [Artifact Repos](#artifact-repos)
  * [BaaS](#baas)
  * [Low-code Platform](#low-code-platform)
  * [CDN and Protection](#cdn-and-protection)
  * [CI and CD](#ci-and-cd)
  * [CMS](#cms)
  * [Code Generation](#code-generation)
  * [Code Quality](#code-quality)
  * [Code Search and Browsing](#code-search-and-browsing)
  * [Crash and Exception Handling](#crash-and-exception-handling)
  * [Data Visualization on Maps](#data-visualization-on-maps)
  * [Managed Data Services](#managed-data-services)
  * [Design and UI](#design-and-ui)
  * [Design Inspiration](#design-inspiration)
  * [Dev Blogging Sites](#dev-blogging-sites)
  * [DNS](#dns)
  * [Docker Related](#docker-related)
  * [Domain](#domain)
  * [Education and Career Development](#education-and-career-development)
  * [Email](#email)
  * [Feature Toggles Management Platforms](#feature-toggles-management-platforms)
  * [Font](#font)
  * [Forms](#forms)
  * [Generative AI](#generative-ai)
  * [IaaS](#iaas)
  * [IDE and Code Editing](#ide-and-code-editing)
  * [International Mobile Number Verification API and SDK](#international-mobile-number-verification-api-and-sdk)
  * [Issue Tracking and Project Management](#issue-tracking-and-project-management)
  * [Log Management](#log-management)
  * [Mobile App Distribution and Feedback](#mobile-app-distribution-and-feedback)
  * [Management Systems](#management-system)
  * [Messaging and Streaming](#messaging-and-streaming)
  * [Miscellaneous](#miscellaneous)
  * [Monitoring](#monitoring)
  * [PaaS](#paas)
  * [Package Build System](#package-build-system)
  * [Payment and Billing Integration](#payment-and-billing-integration)
  * [Privacy Management](#privacy-management)
  * [Screenshot APIs](#screenshot-apis)
  * [Flutter Related and Building IOS Apps without Mac](#flutter-related-and-building-ios-apps-without-mac)
  * [Search](#search)
  * [Security and PKI](#security-and-pki)
  * [Authentication, Authorization, and User Management](#authentication-authorization-and-user-management)
  * [Source Code Repos](#source-code-repos)
  * [Storage and Media Processing](#storage-and-media-processing)
  * [Tunneling, WebRTC, Web Socket Servers and Other Routers](#tunneling-webrtc-web-socket-servers-and-other-routers)
  * [Testing](#testing)
  * [Tools for Teams and Collaboration](#tools-for-teams-and-collaboration)
  * [Translation Management](#translation-management)
  * [Visitor Session Recording](#visitor-session-recording)
  * [Web Hosting](#web-hosting)
  * [Commenting Platforms](#commenting-platforms)
  * [Browser based hardware emulation](#browser-based-hardware-emulation-written-in-javascript)
  * [Remote Desktop Tools](#remote-desktop-tools)
  * [Game Development](#game-development)
  * [Other Free Resources](#other-free-resources)

## Major Cloud Providers

  * [Google Cloud Platform](https://cloud.google.com)
    * App Engine - 28 frontend instance hours per day, nine backend instance hours per day
    * Cloud Firestore - 1GB storage, 50,000 reads, 20,000 writes, 20,000 deletes per day
    * Compute Engine - 1 non-preemptible e2-micro, 30GB HDD, 5GB snapshot storage (restricted to certain regions), 1 GB network egress from North America to all region destinations (excluding China and Australia) per month
    * Cloud Storage - 5GB, 1GB network egress
    * Cloud Shell - Web-based Linux shell/primary IDE with 5GB of persistent storage. 60 hours limit per week
    * Cloud Pub/Sub - 10GB of messages per month
    * Cloud Functions - 2 million invocations per month (includes both background and HTTP invocations)
    * Cloud Run - 2 million requests per month, 360,000 GB-seconds memory, 180,000 vCPU-seconds of compute time, 1 GB network egress from North America per month
    * Google Kubernetes Engine - No cluster management fee for one zonal cluster. Each user node is charged at standard Compute Engine pricing
    * BigQuery - 1 TB of querying per month, 10 GB of storage each month
    * Cloud Build - 120 build-minutes per day
    * Cloud Source Repositories - Up to 5 Users, 50 GB Storage, 50 GB Egress
    * [Google Colab](https://colab.research.google.com/) - Free Jupyter Notebooks development environment.
    * [Firebase Studio](https://firebase.studio) Google Firebase Studio (formerly Project IDX). Online VSCode running on Google Cloud.
    * Full, detailed list - https://cloud.google.com/free

  * [Amazon Web Services](https://aws.amazon.com)
    * [CloudFront](https://aws.amazon.com/cloudfront/) - 1TB egress per month and 2M Function invocations per month
    * [CloudWatch](https://aws.amazon.com/cloudwatch/) - 10 custom metrics and ten alarms
    * [CodeBuild](https://aws.amazon.com/codebuild/) - 100min of build time per month
    * [CodeCommit](https://aws.amazon.com/codecommit/) - 5 active users,50GB storage, and 10000 requests per month
    * [CodePipeline](https://aws.amazon.com/codepipeline/) - 1 active pipeline per month
    * [DynamoDB](https://aws.amazon.com/dynamodb/) - 25GB NoSQL DB
    * [EC2](https://aws.amazon.com/ec2/) - 750 hours per month of t2.micro or t3.micro(12mo). 100GB egress per month
    * [EBS](https://aws.amazon.com/ebs/) - 30GB per month of General Purpose (SSD) or Magnetic(12mo)
    * [Elastic Load Balancing](https://aws.amazon.com/elasticloadbalancing/) - 750 hours per month(12mo)
    * [RDS](https://aws.amazon.com/rds/) - 750 hours per month of db.t2.micro, db.t3.micro, or db.t4g.micro, 20GB of General Purpose (SSD) storage, 20GB of storage backups(12 mo)
    * [S3](https://aws.amazon.com/s3/) - 5GB Standard object storage, 20K Get requests and 2K Put requests(12 mo)
    * [Glacier](https://aws.amazon.com/glacier/) - 10GB long-term object storage
    * [Lambda](https://aws.amazon.com/lambda/) - 1 million requests per month
    * [SNS](https://aws.amazon.com/sns/) - 1 million publishes per month
    * [SES](https://aws.amazon.com/ses/) - 3.000 messages per month (12mo)
    * [SQS](https://aws.amazon.com/sqs/) - 1 million messaging queue requests
    * Full, detailed list - https://aws.amazon.com/free/

  * [Microsoft Azure](https://azure.microsoft.com)
    * [Virtual Machines](https://azure.microsoft.com/services/virtual-machines/) - 1 B1S Linux VM, 1 B1S Windows VM (12mo)
    * [App Service](https://azure.microsoft.com/services/app-service/) - 10 web, mobile, or API apps (60 CPU minutes/day)
    * [Functions](https://azure.microsoft.com/services/functions/) - 1 million requests per month
    * [DevTest Labs](https://azure.microsoft.com/services/devtest-lab/) - Enable fast, easy, and lean dev-test environments
    * [Active Directory](https://azure.microsoft.com/services/active-directory/) - 500,000 objects
    * [Active Directory B2C](https://azure.microsoft.com/services/active-directory/external-identities/b2c/) - 50,000 monthly stored users
    * [Azure DevOps](https://azure.microsoft.com/services/devops/) - 5 active users, unlimited private Git repos
    * [Azure Pipelines](https://azure.microsoft.com/services/devops/pipelines/) — 10 free parallel jobs with unlimited minutes for open source for Linux, macOS, and Windows
    * [Microsoft IoT Hub](https://azure.microsoft.com/services/iot-hub/) - 8,000 messages per day
    * [Load Balancer](https://azure.microsoft.com/services/load-balancer/) - 1 free public load-balanced IP (VIP)
    * [Notification Hubs](https://azure.microsoft.com/services/notification-hubs/) - 1 million push notifications
    * [Bandwidth](https://azure.microsoft.com/pricing/details/bandwidth/) - 15GB Inbound(12mo) & 5GB egress per month
    * [Cosmos DB](https://azure.microsoft.com/services/cosmos-db/) - 25GB storage and 1000 RUs of provisioned throughput
    * [Static Web Apps](https://azure.microsoft.com/pricing/details/app-service/static/) — Build, deploy, and host static apps and serverless functions with free SSL, Authentication/Authorization, and custom domains
    * [Storage](https://azure.microsoft.com/services/storage/) - 5GB LRS File or Blob storage (12mo)
    * [Cognitive Services](https://azure.microsoft.com/services/cognitive-services/) - AI/ML APIs (Computer Vision, Translator, Face detection, Bots, etc) with free tier including limited transactions
    * [Cognitive Search](https://azure.microsoft.com/services/search/#features) - AI-based search and indexation service, free for 10,000 documents
    * [Azure Kubernetes Service](https://azure.microsoft.com/services/kubernetes-service/) - Managed Kubernetes service, free cluster management
    * [Event Grid](https://azure.microsoft.com/services/event-grid/) - 100K ops/month
    * Full, detailed list - https://azure.microsoft.com/free/

  * [Oracle Cloud](https://www.oracle.com/cloud/)
    * Compute
       - 2 AMD-based Compute VMs with 1/8 OCPU and 1 GB memory each
       - 4 Arm-based Ampere A1 cores and 24 GB of memory usable as one VM or up to 4 VMs
       - Instances will be reclaimed when [deemed idle](https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm#compute__idleinstances)
    * Block Volume - 2 volumes, 200 GB total (used for compute)
    * Object Storage - 10 GB
    * Load balancer - 1 instance with 10 Mbps
    * Databases - 2 DBs, 20 GB each
    * Monitoring - 500 million ingestion data points, 1 billion retrieval datapoints
    * Bandwidth - 10 TB egress per month, speed limited to 50 Mbps on x64-based VM, 500 Mbps * core count on ARM-based VM
    * Public IP - 2 IPv4 for VMs, 1 IPv4 for load balancer
    * Notifications - 1 million delivery options per month, 1000 emails sent per month
    * Full, detailed list - https://www.oracle.com/cloud/free/

  * [IBM Cloud](https://www.ibm.com/cloud/free/)
    * Cloudant database - 1 GB of data storage
    * Db2 database - 100MB of data storage
    * API Connect - 50,000 API calls per month
    * Availability Monitoring - 3 million data points per month
    * Log Analysis - 500MB of daily log
    * Full, detailed list - https://www.ibm.com/cloud/free/

  * [Cloudflare](https://www.cloudflare.com/)
    * [Application Services](https://www.cloudflare.com/plans/) - Free DNS for an unlimited number of domains, DDoS Protection, CDN along with free SSL, Firewall rules and page rules,  WAF, Bot Mitigation, Free Unmetered Rate Limiting - 1 rule per domain, Analytics, Email forwarding
    * [Zero Trust & SASE](https://www.cloudflare.com/plans/zero-trust-services/) - Up to 50 Users, 24 hours of activity logging, three network locations
    * [Cloudflare Tunnel](https://www.cloudflare.com/products/tunnel/) -  You can expose locally running HTTP port over a tunnel to a random subdomain on trycloudflare.com use [Quick Tunnels](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/trycloudflare/), No account required. More features (TCP tunnel, Load balancing, VPN) in [Zero Trust](https://www.cloudflare.com/products/zero-trust/) Free Plan.
    * [Workers](https://developers.cloudflare.com/workers/) - Deploy serverless code for free on Cloudflare's global network—100k daily requests.
    * [Workers KV](https://developers.cloudflare.com/kv) - 100k read requests per day, 1000 write requests per day, 1000 delete requests per day, 1000 list requests per day, 1 GB stored data
    * [R2](https://developers.cloudflare.com/r2/) - 10 GB per month, 1 million Class A operations per month, 10 million Class B operations per month
    * [D1](https://developers.cloudflare.com/d1/) - 5 million rows read per day, 100k rows written per day, 1 GB storage
    * [Pages](https://developers.cloudflare.com/pages/) - Develop and deploy your web apps on Cloudflare's fast, secure global network. Five hundred monthly builds, 100 custom domains, Integrated SSL, unlimited accessible seats, unlimited preview deployments, and full-stack capability via Cloudflare Workers integration.
    * [Queues](https://developers.cloudflare.com/queues/) - 1 million operations per month
    * [TURN](https://developers.cloudflare.com/calls/turn/) – 1TB of free (outgoing) traffic per month.

  * [Zoho](https://www.zoho.com) — Started as an e-mail provider but now provides a suite of services, some of which have free plans. List of services having free plans :
    * [Email](https://zoho.com/mail) Free for 5 users. 5GB/user & 25 MB attachment limit, one domain.
    * [Zoho Assist](https://www.zoho.com/assist) — Zoho Assist's forever free plan includes one concurrent remote support license and Access to 5 unattended computer licenses for unlimited duration available for both professional and personnel use.
    * [Sprints](https://zoho.com/sprints) Free for 5 users,5 Projects & 500MB storage.
    * [Docs](https://zoho.com/docs) — Free for 5 users with 1 GB upload limit & 5GB storage. Zoho Office Suite (Writer, Sheets & Show) comes bundled.
    * [Projects](https://zoho.com/projects) — Free for 3 users, 2 projects & 10 MB attachment limit. The same plan applies to [Bugtracker](https://zoho.com/bugtracker).
    * [Connect](https://zoho.com/connect) — Team Collaboration free for 25 users with three groups, three custom apps, 3 Boards, 3 Manuals, and 10 Integrations along with channels, events & forums.
    * [Meeting](https://zoho.com/meeting) — Meetings with upto 3 meeting participants & 10 Webinar attendees.
    * [Vault](https://zoho.com/vault) — Password Management is accessible for Individuals.
    * [Showtime](https://zoho.com/showtime) — Yet another Meeting software for training for a remote session of up to 5 attendees.
    * [Notebook](https://zoho.com/notebook) — A free alternative to Evernote.
    * [Wiki](https://zoho.com/wiki) — Free for three users with 50 MB storage, unlimited pages, zip backups, RSS & Atom feed, access controls & customizable CSS.
    * [Subscriptions](https://zoho.com/subscriptions) — Recurring Billing management free for 20 customers/subscriptions & 1 user with all the payment hosting done by Zoho. The last 40 subscription metrics are stored
    * [Checkout](https://zoho.com/checkout) — Product Billing management with 3 pages & up to 50 payments.
    * [Desk](https://zoho.com/desk) — Customer Support management with three agents, private knowledge base, and email tickets. Integrates with [Assist](https://zoho.com/assist) for one remote technician & 5 unattended computers.
    * [Cliq](https://zoho.com/cliq) — Team chat software with 100 GB storage, unlimited users, 100 users per channel & SSO.
    * [Campaigns](https://zoho.com/campaigns) - Email Marketing
    * [Forms](https://zoho.com/forms) - Form Creator
    * [Sign](https://zoho.com/sign) - Paperless Signatures
    * [Surveys](https://zoho.com/surveys) - Online Surveys
     * [Bookings](https://zoho.com/bookings) - Appointment Scheduling

**[⬆️ Back to Top](#table-of-contents)**

## Cloud management solutions

  * [Brainboard](https://www.brainboard.co) - Collaborative solution to visually build and manage cloud infrastructures from end-to-end.
  * [Cloud 66](https://www.cloud66.com/) - Free for personal projects (includes one deployment server, one static site), Cloud 66 gives you everything you need to build, deploy, and grow your applications on any cloud without the headache of the “server stuff.”.
  * [deployment.io](https://deployment.io) - Deployment.io helps developers automate deployments on AWS. On our free tier, a developer (single user) can deploy unlimited static sites, web services, and environments. We provide 10 job executions free per month with previews and auto-deploys included in the free tier.
  * [Pulumi](https://www.pulumi.com/) — Modern infrastructure as a code platform that allows you to use familiar programming languages and tools to build, deploy, and manage cloud infrastructure.
  * [scalr.com](https://scalr.com/) - Scalr is a Terraform Automation and COllaboration (TACO) product used to better collaboration and automation on infrastructure and configurations managed by Terraform. Full Terraform CLI support, OPA integration, and a hierarchical configuration model. No SSO tax. All features are included. Use up to 50 runs/month for free.

**[⬆️ Back to Top](#table-of-contents)**

## Source Code Repos

  * [Bitbucket](https://bitbucket.org/) — Unlimited public and private Git repos for up to 5 users with Pipelines for CI/CD
  * [Codeberg](https://codeberg.org/) — Unlimited public and private Git repos for free and open-source projects (with unlimited collaborators). Powered by [Forgejo](https://forgejo.org/). Static website hosting with [Codeberg Pages](https://codeberg.page/). CI/CD hosting with [Codeberg's CI](https://docs.codeberg.org/ci/). Translating hosting with [Codeberg Translate](https://translate.codeberg.org/). Includes Package and Container hosting, Project management, and Issue Tracking
  * [framagit.org](https://framagit.org/) — Framagit is the software forge of Framasoft based on the Gitlab software includes CI, Static Pages, Project pages and Issue tracking.
  * [GitGud](https://gitgud.io) — Unlimited private and public repositories. Free forever. Powered by GitLab & Sapphire. CI/CD not provided.
  * [GitHub](https://github.com/) — Unlimited public repositories and unlimited private repositories (with unlimited collaborators). Includes CI/CD, Development Environment, Static Hosting, Package and Container hosting, Project management and AI Copilot
  * [gitlab.com](https://about.gitlab.com/) — Unlimited public and private Git repos with up to 5 collaborators. Includes CI/CD, Static Hosting, Container Registry, Project Management and Issue Tracking
  * [heptapod.net](https://foss.heptapod.net/) — Heptapod is a friendly fork of GitLab Community Edition providing support for Mercurial
  * [Pagure.io](https://pagure.io) — Pagure.io is a free and open source software code collaboration platform for FOSS-licensed projects, Git-based
  * [pijul.com](https://pijul.com/) - Unlimited free and open source distributed version control system. Its distinctive feature is based on a sound theory of patches, which makes it easy to learn, use, and distribute. Solves many problems of git/hg/svn/darcs.
  * [projectlocker.com](https://projectlocker.com) — One free private project (Git and Subversion) with 50 MB of space
  * [RocketGit](https://rocketgit.com) — Repository Hosting based on Git. Unlimited Public and private repositories.
  * [savannah.gnu.org](https://savannah.gnu.org/) - Serves as a collaborative software development management system for free Software projects (for GNU Projects)
  * [savannah.nongnu.org](https://savannah.nongnu.org/) - Serves as a collaborative software development management system for free Software projects (for non-GNU projects)

**[⬆️ Back to Top](#table-of-contents)**

## APIs, Data, and ML

  * [Abstract API](https://www.abstractapi.com) — API suite for various use cases, including IP geolocation, gender detection, or email validation.
  * [Apify](https://www.apify.com/) — Web scraping and automation platform to create an API for any website and extract data. Ready-made scrapers, integrated proxies, and custom solutions. Free plan with $5 platform credits included every month.
  * [APITemplate.io](https://apitemplate.io) - Auto-generate images and PDF documents with a simple API or automation tools like Zapier & Airtable. No CSS/HTML is required. The free plan comes with 50 images/month and three templates.
  * [APIVerve](https://apiverve.com) - Get instant access to over 120+ APIs for free, built with quality, consistency, and reliability in mind. The free plan covers up to 50 API Tokens per month. (Possibly taken down, 2025-06-25)
  * [Arize AI](https://arize.com/) - Machine learning observability for model monitoring and root-causing issues such as data quality and performance drift. Free up to two models.
  * [Beeceptor](https://beeceptor.com) - No-code, cloud-based platform for mocking and debugging multi-protocol APIs (REST, SOAP, gRPC & GraphQL), providing instant servers with rules-based logic, CRUD & stateful mocking, proxying, and CORS management for faster integration and testing. The free plan includes 50 requests per day and provides a public dashboard/endpoint where anyone with the dashboard URL can view submitted requests and responses.
  * [BigDataCloud](https://www.bigdatacloud.com/) - Provides fast, accurate, and free (Unlimited or up to 10K-50K/month) APIs for modern web like IP Geolocation, Reverse Geocoding, Networking Insights, Email and Phone Validation, Client Info and more.
  * [Browse AI](https://www.browse.ai) — Extracting and monitoring data on the web. 1k credits per month for free, equals 1k concurrent requests.
  * [BrowserCat](https://www.browsercat.com) - Headless browser API for automation, scraping, AI agent web access, image/pdf generation, and more. Free plan with 1k requests per month.
  * [Calendarific](https://calendarific.com) - Enterprise-grade Public holiday API service for over 200 countries. The free plan includes 500 calls per month.
  * [Canopy](https://www.canopyapi.co/) - GraphQL API for Amazon.com product, search, and category data. The free plan includes 100 calls per month.
  * [CarAPI.dev](https://carapi.dev) — Comprehensive automotive data API with VIN decoding, stolen vehicle checks, vehicle valuation, inspection data, and more. Free tier includes 100 requests/month across all 9 endpoints.
  * [Cloudmersive](https://cloudmersive.com/) — Utility API platform with full access to expansive API Library including Document Conversion, Virus Scanning, and more with 600 calls/month, North America AZ only, 2.5MB maximum file size.
  * [Colaboratory](https://colab.research.google.com) — Free web-based Python notebook environment with Nvidia Tesla K80 GPU.
  * [CometML](https://www.comet.com/site/) - The MLOps platform for experiment tracking, model production management, model registry, and complete data lineage, covering your workflow from training to production. Free for individuals and academics.
  * [Commerce Layer](https://commercelayer.io) - Composable commerce API that can build, place, and manage orders from any front end. The developer plan allows 100 orders per month and up to 1,000 SKUs for free.
  * [Composio](https://composio.dev/) - Integration platform for AI Agents and LLMs. Integrate over 200+ tools across the agentic internet.
  * [Conversion Tools](https://conversiontools.io/) - Online File Converter for documents, images, video, audio, and eBooks. REST API is available. Libraries for Node.js, PHP, Python. Support files up to 50 GB (for paid plans). The free tier is limited by file size (20MB) and number of conversions (30/Day, 300/Month).
  * [Country-State-City Microservice API](https://country-state-city.rebuscando.info/) - API and Microservice to provides a wide range of information including countries, regions, provinces, cities, postal codes, and much more. The free tier includes up to 100 requests per day.
  * [Coupler](https://www.coupler.io/) - Data integration tool that syncs between apps. It can create live dashboards and reports, transform and manipulate values, and collect and back up insights. The free plan is limited to one user, data connection, data source, and data destination. Also requires manual data refresh.
  * [CraftMyPDF](https://craftmypdf.com) - Auto-Generate PDF documents from reusable templates with a drop-and-drop editor and a simple API. The free plan comes with 100 PDFs/month and three templates.
  * [Cube](https://cube.dev/) - Cube helps data engineers and application developers access data from modern data stores, organize it into consistent definitions, and deliver it to every application. The fastest way to use Cube is with Cube Cloud, which has a free tier limited to 1,000 queries per day.
  * [CurlHub](https://curlhub.io) — Proxy service for inspecting and debugging API calls. The free plan includes 10,000 requests per month.
  * [CurrencyScoop](https://currencyscoop.com) - Realtime currency data API for fintech apps. The free plan includes 5,000 calls per month.
  * [CustomJS](https://www.customjs.io) - HTML to PDF or PDF to PNG/Text & PDF merging/extraction/merging APIs. Free tier has 600 calls a month.
  * [Data Fetcher](https://datafetcher.com) - Connect Airtable to any application or API with no code. Postman-like interface for running API requests in Airtable. Pre-built integrations with dozens of apps. The free plan includes 100 runs per month.
  * [Data Miner](https://dataminer.io/) - A browser extension (Google Chrome, MS Edge) for data extraction from web pages CSV or Excel. The free plan gives you 500 pages/month.
  * [Dataimporter.io](https://www.dataimporter.io) - Tool for connecting, cleaning, and importing data into Salesforce. Free Plan includes up to 20,000 records per month.
  * [Datalore](https://datalore.jetbrains.com) - Python notebooks by Jetbrains. Includes 10 GB of storage and 120 hours of runtime each month.
  * [DB Designer](https://www.dbdesigner.net/) — Cloud-based Database schema design and modeling tool with a free starter plan of 2 Database models and ten tables per model.
  * [DB-IP](https://db-ip.com/api/free) - Free IP geolocation API with 1k request per IP per day.lite database under the CC-BY 4.0 License is free too.
  * [DeepAR](https://developer.deepar.ai) — Augmented reality face filters for any platform with one SDK. The free plan provides up to 10 monthly active users (MAU) and tracks up to 4 faces
  * [Deepnote](https://deepnote.com) - A new data science notebook. Jupyter is compatible with real-time collaboration and running in the cloud. The free tier includes unlimited personal projects, unlimited basic machines with 5GB RAM and 2vCPU, and teams with up to 3 editors.
  * [DiffJSON](https://diffjson.com) - An online tool for comparing differences between two JSON data structures, helping you quickly locate the differences in JSON data.
  * [Disease.sh](https://disease.sh/) — A free API providing accurate data for building the Covid-19 related useful Apps.
  * [Doczilla](https://www.doczilla.app/) — SaaS API empowering the generation of screenshots or PDFs directly from HTML/CSS/JS code. The free plan allows 250 documents month.
  * [Doppio](https://doppio.sh/) — Managed API to generate and privately store PDFs and Screenshots using top rendering technology. The free plan allows 400 PDFs and Screenshots per month.
  * [drawDB](https://drawdb.app/) — Free and open-source online database diagram editor with no signup required.
  * [DynamicDocs](https://advicement.io) - Generate PDF documents with JSON to PDF API based on LaTeX templates. The free plan allows 50 API calls per month and access to a library of templates.
  * [Earnings Feed](https://earningsfeed.com/api) - Real-time SEC filings, insider trades, and institutional holdings API. Free tier includes 15 requests per minute.
  * [Export SDK](https://exportsdk.com) - PDF generator API with drag-and-drop template editor that provides an SDK and no-code integrations. The free plan has 250 monthly pages, unlimited users, and three templates.
  * [ExtendsClass](https://extendsclass.com/rest-client-online.html) - Free web-based HTTP client to send HTTP requests.
  * [Financial Data](https://financialdata.net/) - Stock market and financial data API. Free plan allows 300 requests per day.
  * [FormatJSONOnline.com](https://formatjsononline.com) - A free, browser-based tool to format, validate,compare and minify JSON data instantly.
  * [FraudLabs Pro](https://www.fraudlabspro.com) — Screen an order transaction for credit card payment fraud. This REST API will detect all possible fraud traits based on the input parameters of an order. The Free Micro plan has 500 transactions per month.
  * [FreeIPAPI](https://freeipapi.com) - Free, Fast and Reliable IP Geolocation API for commercial and non-commercial users available in JSON
  * [Geolocated.io](https://geolocated.io) — IP Geolocation API with multi-continent servers, offering a free plan with 2,000 requests per day.
  * [Hex](https://hex.tech/) - a collaborative data platform for notebooks, data apps, and knowledge libraries. Free community tier with up to five projects.
  * [Hook0](https://www.hook0.com/) - Hook0 is an open-source Webhooks-as-a-service (WaaS) that makes it easy for online products to provide webhooks. Dispatch up to 100 events/day with seven days of history retention for free.
  * [Hoppscotch](https://hoppscotch.io) - A free, fast, and beautiful API request builder.
  * [huggingface.co](https://huggingface.co) - Build, train, and deploy NLP models for Pytorch, TensorFlow, and JAX. Free up to 30k input characters/mo.
  * [Insomnia](https://insomnia.rest) - Open-source API client for designing and testing APIs, it supports REST and GraphQL
  * [Invantive Cloud](https://cloud.invantive.com/) — Access over 70 (cloud)platforms such as Exact Online, Twinfield, ActiveCampaign or Visma using Invantive SQL or OData4 (typically Power BI or Power Query). Includes data replication and exchange. Free plan for developers and implementation consultants. Free for specific platforms with limitations in data volumes.
  * [IP Geolocation API by ipwho.org](https://ipwho.org/) - 2,000 free requests per day. Fast, enterprise grade API at non-enterprise prices. Trusted by developers, corporate, government and education clients. Servers in 12+ regions.
  * [IP Geolocation API](https://www.abstractapi.com/ip-geolocation-api) — IP Geolocation API from Abstract - Allows 1,000 free requests.
  * [IP Geolocation](https://ipgeolocation.io/) — IP Geolocation API - Forever free plan for developers with a 1,000 requests per day limit.
  * [ip-api](https://ip-api.com) — IP Geolocation API, Free for non-commercial use, no API key required, limited to 45 req/minute from the same IP address for the free plan.
  * [IP.City](https://ip.city) — 100 Free IP geolocation requests per day
  * [IP2Location.io](https://www.ip2location.io/) — Freemium, fast, and reliable IP geolocation API. Get data like city, coordinates, ISP, ASN, AS data and more. The free plan includes 50k credits per month. IP2Location.io also offers 500 free WHOIS and hosted domain lookups per month. See domain registration details and find domains hosted on a specific IP. Upgrade to a paid plan for more features.
  * [ipaddress.sh](https://ipaddress.sh) — Simple service to get a public IP address in different [formats](https://about.ipaddress.sh/).
  * [ipapi.is](https://ipapi.is/) - A reliable IP Address API from Developers for Developers with the best Hosting Detection capabilities that exist. The free plan offers 1000 lookups without signup.
  * [ipapi](https://ipapi.co/) - IP Address Location API by Kloudend, Inc - A reliable geolocation API built on AWS, trusted by Fortune 500. The free tier offers 30k lookups/month (1k/day) without signup.
  * [ipbase.com](https://ipbase.com) - IP Geolocation API - Forever free plan that spans 150 monthly requests.
  * [IPinfo](https://ipinfo.io/) — Fast, accurate, and free (up to 50k/month) IP address data API. Offers APIs with details on geolocation, companies, carriers, IP ranges, domains, abuse contacts, and more. All paid APIs can be trialed for free.
  * [IPLocate](https://www.iplocate.io) — IP Geolocation API, free up to 1,000 requests/day. Includes proxy/VPN/hosting detection, ASN data, IP to Company, and more. IPLocate also offers free downloadable IP to Country and IP to ASN databases in CSV or GeoIP-compatible MMDB formats.
  * [IPTrace](https://iptrace.io) — An embarrassingly simple API that provides your business with reliable and helpful IP geolocation data with 50,000 free lookups per month.
  * [JSON IP](https://getjsonip.com) — Returns the Public IP address of the client it is requested from. No registration is required for the free tier. Using CORS, data can be requested using client-side JS directly from the browser. Useful for services monitoring change in client and server IPs. Unlimited Requests.
  * [JSON to Table](https://jsontotable.org) - Convert JSON into an interactive table for quick viewing, editing, and sharing online.
  * [JSON2Video](https://json2video.com) - A video editing API to automate video marketing and social media videos, programmatically or with no code.
  * [JSONGrid](https://jsongrid.com) - Free tool to Visualize, Edit, Filter complex JSON data into beautiful tabular Grid. Save and Share JSON data over link link.
  * [JSONing](https://jsoning.com/api/) — Create a fake REST API from a JSON object, and customize HTTP status codes, headers, and response bodies.
  * [JSONSwiss](https://www.jsonswiss.com/) - JSONSwiss is a powerful online JSON viewer, editor, and validator. Format, visualize, search, and manipulate JSON data with AI-powered repair, tree view, table view, code generation in 12+ programming languages, convert json to csv, xml, yaml, properties and more.
  * [KillBait API](https://killbait.com/api/doc) - KillBait API allows users to submit URLs for content evaluation, detecting potential clickbait and categorizing articles. The API is designed for moderate publishing frequency, with limits of 1 submission per hour and 10 per day. Media partners can request higher limits.
  * [Kreya](https://kreya.app) — Free gRPC GUI client to call and test gRPC APIs. Can import gRPC APIs via server reflection.
  * [LoginLlama](https://loginllama.app) - A login security API to detect fraudulent and suspicious logins and notify your customers. Free for 1,000 logins per month.
  * [Market Data API](https://www.marketdata.app) - Provides real-time and historical financial data for stocks, options, mutual funds, and more. The Free Forever API tier allows for 100 daily API requests at no charge.
  * [Maxim AI](https://getmaxim.ai/) - Simulate, evaluate, and observe your AI agents. Maxim is an end-to-end evaluation and observability platform, helping teams ship their AI agents reliably and >5x faster. Free forever for indie developers and small teams (3 seats).
  * [microlink.io](https://microlink.io/) – It turns any website into data such as metatags normalization, beauty link previews, scraping capabilities, or screenshots as a service. 50 requests per day, every day free.
  * [Mintlify](https://mintlify.com) — Modern standard for API documentation. Beautiful and easy-to-maintain UI components, in-app search, and interactive playground. Free for 1 editor.
  * [MockAPI](https://www.mockapi.io/) — MockAPI is a simple tool that lets you quickly mock up APIs, generate custom data, and perform operations using a RESTful interface. MockAPI is meant to be a prototyping/testing/learning tool. One project/2 resources per project for free.
  * [Mockerito](https://mockerito.com/) — Free mock REST API service providing realistic data across 9 domains (e-commerce, finance, healthcare, education, recruitment, social media, stock markets, weather, and aviation). No mandatory signup, no API keys, unlimited requests. Perfect for frontend prototyping, API testing, learning and teaching web development.
  * [Mockfly](https://www.mockfly.dev/) — Mockfly is a trusted development tool for API mocking and feature flag management. Quickly generate and control mock APIs with an intuitive interface. The free tier offers 500 requests per day.
  * [Mocko.dev](https://mocko.dev/) — Proxy your API, choose which endpoints to mock in the cloud and inspect traffic, for free. Speed up your development and integration tests.
  * [Multi-Exit IP Address Checker](https://ip.alstra.ca/) —  A free and simple tool to check your exit IP address across multiple nodes and understand how your IP appears to different global regions and services. Useful for testing rule-based DNS splitting tools such as Control D.
  * [News API](https://newsapi.org) — Search news on the web with code, and get JSON results. Developers get 100 queries free each day. Articles have a 24 hour delay.
  * [numlookupapi.com](https://numlookupapi.com) - Free phone number validation API - 100 free requests / month.
  * [OCR.Space](https://ocr.space/) — An OCR API parses image and pdf files that return the text results in JSON format. 25,000 requests per month are free and a 1MB file size limit.
  * [OpenAPI3 Designer](https://openapidesigner.com/) — Visually create Open API 3 definitions for free.
  * [Parseur](https://parseur.com) — 20 free pages/month: Extract data from PDFs, emails. AI powered. Full API access.
  * [PDF-API.io](https://pdf-api.io) - PDF Automation API, visual template editor or HTML to PDF, dynamic data integration, and PDF rendering with an API. The free plan comes with one template, 100 PDFs/month.
  * [PDFBolt](https://pdfbolt.com) - Developer-focused PDF generation API designed with privacy in mind. It offers Stripe-inspired documentation and includes 500 free PDF conversions per month.
  * [pdfEndpoint.com](https://pdfendpoint.com) - Effortlessly convert HTML or URLs to PDF with a simple API. One hundred conversions per month for free.
  * [Pixela](https://pixe.la/) - Free daystream database service. All operations are performed by API. Visualization with heat maps and line graphs is also possible.
  * [Postman](https://postman.com) — Simplify workflows and create better APIs – faster – with Postman, a collaboration platform for API development. Use the Postman App for free forever. Postman cloud features are also free forever with certain limits.
  * [PrefectCloud](https://www.prefect.io/cloud/) — A complete platform for dataflow automation. Free plan includes 5 deployed workflows and 500 minutes of serverless compute credits per month.
  * [Preset Cloud](https://preset.io/) - A hosted Apache Superset service. Forever free for teams of up to 5 users, featuring unlimited dashboards and charts, a no-code chart builder, and a collaborative SQL editor.
  * [ProxySentry](https://proxysentry.io/) - IP API that detects residential proxies and VPNs. ProxySentry.io offers a free tier with 10k requests per month on rapidapi.com.
  * [Reducto](https://reducto.ai) - Turn any unstructured documents (PDF, XLSX, JPG, PPTX, etc.) into structured JSON data. Parse, extract data, and edit PDF forms. Free tier with 15k free credits and pay-as-you-go.
  * [Rendi](https://rendi.dev) - FFmpeg API - A REST API for FFmpeg, run FFmpeg online without handling the infrastructure. Free tier with monthly processing quota and 4 vCPUs available.
  * [RequestBin.com](https://requestbin.com) — Create a free endpoint to which you can send HTTP requests. Any HTTP requests sent to that endpoint will be recorded with the associated payload and headers so you can observe recommendations from webhooks and other services.
  * [ROBOHASH](https://robohash.org/) - Web service to generate unique and cool images from any text.
  * [Scraper's Proxy](https://scrapersproxy.com) — Simple HTTP proxy API for scraping. Scrape anonymously without having to worry about restrictions, blocks, or captchas. First 100 successful scrapes per month free including javascript rendering (more available if you contact support).
  * [ScrapingAnt](https://scrapingant.com/) — Headless Chrome scraping API and free checked proxies service. Javascript rendering, premium rotating proxies, CAPTCHAs avoiding. Free 10,000 API credits.
  * [SerpApi](https://serpapi.com/) - Real-time search engine scraping API. Returns structured JSON results for Google, YouTube, Bing, Baidu, Walmart, and many other machines. The free plan includes 100 successful API calls per month.
  * [Sheetson](https://sheetson.com) - Instantly turn any Google Sheets into a RESTful API. Free plan available, including 1,000 free rows per sheet.
  * [Simplescraper](https://simplescraper.io) — Trigger your webhook after each operation. The free plan includes 100 cloud scrape credits.
  * [Siterelic](https://siterelic.com/) - Siterelic API lets you take screenshots, audit websites, TLS scan, DNS lookup, test TTFB, and more. The free plan offers 100 API requests per month.
  * [SmartParse](https://smartparse.io) - SmartParse is a data migration and CSV to API platform that offers time- and cost-saving developer tools. The Free tier includes 300 Processing Units per month, Browser uploads, Data quarantining, Circuit breakers, and Job Alerts.
  * [Sofodata](https://www.sofodata.com/) - Create secure RESTful APIs from CSV files. Upload a CSV file and instantly access the data via its API allowing faster application development. The free plan includes 2 APIs and 2,500 API calls per month. You don't need a credit card.
  * [Sqlable](https://sqlable.com/) - A collection of free online SQL tools, including an SQL formatter and validator, SQL regex tester, fake data generator, and interactive database playgrounds.
  * [Supportivekoala](https://supportivekoala.com/) — Allows you to autogenerate images by your input via templates. The free plan allows you to create up to 50 images per month.
  * [Svix](https://www.svix.com/) - Webhooks as a Service. Send up to 50,000 messages/month for free.
  * [Tavily AI](https://tavily.com/) - API for online search and rapid insights and comprehensive research, with the capability of organization of research results. 1000 request/month for the Free tier with No credit card required.
  * [The IP API](https://theipapi.com/) - IP Geolocation API with 1000 free requests / day. Provides information about the location of an IP address, including country, city, region, and more.
  * [TinyMCE](https://www.tiny.cloud) - rich text editing API. Core features are free for unlimited usage.
  * [Tomorrow.io Weather API](https://www.tomorrow.io/weather-api/) - Offers free plan of weather API. Provides accurate and up-to-date weather forecasting with global coverage, historical data and weather monitoring solutions.
  * [Treblle](https://www.treblle.com) - Treblle helps teams build, ship, and govern APIs. With advanced API log aggregation, observability, docs, and debugging. You get all features for free, but there is a limit of up to 250k requests per month on the free tier.
  * [UniRateAPI](https://unirateapi.com) – Real-time exchange rates for 590+ currencies and crypto. Unlimited API calls on the free plan, perfect for developers and finance apps.
  * [vatcheckapi.com](https://vatcheckapi.com) - Simple and free VAT number validation API. 150 free validations per month.
  * [WeatherXu](https://weatherxu.com/) — Global weather data including current conditions, hourly and daily forecasts, and weather alerts via our API. Integrating AI models and ML systems to analyze and combine multiple weather models to deliver improved forecast accuracy. Free tier includes 10,000 API calls/month.
  * [WebScraping.AI](https://webscraping.ai) - Simple Web Scraping API with built-in parsing, Chrome rendering, and proxies. Two thousand free API calls per month.
  * [Weights & Biases](https://wandb.ai) — The developer-first MLOps platform. Build better models faster with experiment tracking, dataset versioning, and model management. Free tier for personal projects only, with 100 GB of storage included.
  * [What The Diff](https://whatthediff.ai) - AI-powered code review assistant. The free plan has a limit of 25,000 monthly tokens (~10 PRs).
  * [wolfram.com](https://wolfram.com/language/) — Built-in knowledge-based algorithms in the cloud.
  * [wrapapi.com](https://wrapapi.com/) — Turn any website into a parameterized API. 30k API calls per month.
  * [Zenscrape](https://zenscrape.com/web-scraping-api) — Web scraping API with headless browsers, residentials IPs, and straightforward pricing. One thousand free API calls/month and extra credits for students and non-profits.
  * [Zipcodebase](https://zipcodebase.com) - Free Zip Code API, access to Worldwide Postal Code Data. 5,000 free requests/month.
  * [Zipcodestack](https://zipcodestack.com) - Free Zip Code API and Postal Code Validation. Ten thousand free requests/month.
  * [Zuplo](https://zuplo.com/) - Free API Management platform to design, build, and deploy APIs to the Edge. Add API Key authentication, rate limiting, developer documentation and Monetization to any API in minutes. OpenAPI-native and fully-programmable with web standard apis & Typescript. The free plan offers up to 10 projects, unlimited production edge environments, 1M monthly requests, and 10GB egress.

**[⬆️ Back to Top](#table-of-contents)**

## Artifact Repos

  * [Gemfury](https://gemfury.com) — Private and public artifact repos for Maven, PyPi, NPM, Go Module, Nuget, APT, and RPM repositories. Free for public projects.
  * [jitpack.io](https://jitpack.io/) — Maven repository for JVM and Android projects on GitHub, free for public projects.
  * [paperspace](https://www.paperspace.com/) — Build & scale AI models, Develop, train, and deploy AI applications, free plan: public projects, 5Gb storage, basic instances.
  * [RepoFlow](https://repoflow.io) - RepoFlow Simplifies package management with support for npm, PyPI, Docker, Go, Helm, and more. Try it for free with 10GB storage, 10GB bandwidth, 100 packages, and unlimited users in the cloud, or self-hosted for personal use only.
  * [RepoForge](https://repoforge.io) - Private cloud-hosted repository for Python, Debian, NPM packages and Docker registries. Free plan for open source/public projects.
  * [repsy.io](https://repsy.io) — 1 GB Free private/public Maven Repository.

**[⬆️ Back to Top](#table-of-contents)**

## Tools for Teams and Collaboration

  * [3Cols](https://3cols.com/) - A free cloud-based code snippet manager for personal and collaborative code.
  * [BookmarkOS.com](https://bookmarkos.com) - Free all-on-one bookmark manager, tab manager, and task manager in a customizable online desktop with folder collaboration.
  * [Braid](https://www.braidchat.com/) — Chat app designed for teams. Free for public access group, unlimited users, history, and integrations. also, it provides a self-hostable open-source version.
  * [Calendly](https://calendly.com) — Calendly is the tool for connecting and scheduling meetings. The free plan provides 1 Calendar connection per user and Unlimited sessions. Desktop and Mobile apps are also offered.
  * [cally.com](https://cally.com/) — Find the perfect time and date for a meeting. Simple to use, works great for small and large groups.
  * [Chanty.com](https://chanty.com/) — Chanty is another alternative to Slack. It has a free forever plan for small teams (up to 10) with unlimited public and private conversations, searchable history, unlimited 1:1 audio calls, unlimited voice messages, ten integrations, and 20 GB storage per team.
  * [DevToolLab](https://devtoollab.com) — Online developer tools offering free access to all basic tools, with the ability to auto save one entry per tool, standard processing speed, and community support.
  * [Discord](https://discord.com/) — Chat with public/private rooms. Markdown text, voice, video, and screen sharing capabilities. Free for unlimited users.
  * [Dubble](https://dubble.so/) — Free Step-by-Step Guide creator. Take screenshots, document processes and colloborate with your team. Also supports async screen recording.
  * [Duckly](https://duckly.com/) — Talk and collaborate in real time with your team. Pair programming with IDE, terminal sharing, voice, video, and screen sharing. Free for small teams.
  * [element.io](https://element.io/) — A decentralized and open-source communication tool built on Matrix. Group chats, direct messaging, encrypted file transfers, voice and video chats, and easy integration with other services.
  * [evernote.com](https://evernote.com/) — Tool for organizing information. Share your notes and work together with others
  * [Fibery](https://fibery.io/) — Connected workspace platform. Free for single users, up to 2 GB disk space.
  * [Fibo](https://fibo.dev) - A free online realtime scrum poker tool for agile teams that lets unlimited members estimate story points for faster planning.
  * [Fizzy](https://www.fizzy.do/) - Kanban-based platform for project management and issue tracking. Create public boards, set up webhooks, use card stamping, and track unlimited users — free for up to 1000 items.
  * [flat.social](https://flat.social) - Interactive customizable spaces for team meetings & happy hours socials. Unlimited meetings, free up to 8 concurrent users.
  * [flock.com](https://flock.com) — A faster way for your team to communicate. Free Unlimited Messages, Channels, Users, Apps & Integrations
  * [GitBook](https://www.gitbook.com/) — Platform for capturing and documenting technical knowledge — from product docs to internal knowledge bases and APIs. Free plan for individual developers.
  * [GitDailies](https://gitdailies.com) - Daily reports of your team's Commit and Pull Request activity on GitHub. Includes Push visualizer, peer recognition system, and custom alert builder. The free tier has unlimited users, three repos, and 3 alert configs.
  * [gitter.im](https://gitter.im/) — Chat, for GitHub. Unlimited public and private rooms, free for teams of up to 25
  * [gokanban.io](https://gokanban.io) - Syntax-based, no registration Kanban Board for fast use. Free with no limitations.
  * [Hackmd.io](https://hackmd.io/) - Real time collaboration & writing tool for markdown format docs/files. Like Google Docs but for markdown files. Free unlimited number of "notes", but the number of collaborators (invitee) for private notes & template [will be limited](https://hackmd.io/pricing).
  * [HeySpace](https://hey.space) - Task management tool with chat, calendar, timeline and video calls. Free for up to 5 users.
  * [Huly](https://huly.io/) - All-in-One Project Management Platform (alternative to Linear, Jira, Slack, Notion, Motion) - unlimited users, 10GB storage per workspace, 10GB video(audio) traffic.
  * [Keybase](https://keybase.io/) — Keybase is a FOSS alternative to Slack; it keeps everyone's chats and files safe, from families to communities to companies.
  * [Linkinize](https://linkinize.com) — Bookmark manager for teams with tagging, multi-workspaces, and collaboration. Free plan includes 4 workspaces and 10 team members.
  * [Lockitbot](https://www.lockitbot.com/) — Reserve and lock shared resources within Slack like Rooms, Dev environments , servers etc. Free for upto 2 resources
  * [meet.jit.si](https://meet.jit.si/) — One-click video conversations, and screen sharing, for free
  * [Miro](https://miro.com/) - Scalable, secure, cross-device, and enterprise-ready collaboration whiteboard for distributed teams. With a freemium plan.
  * [Notion](https://www.notion.so/) - Notion is a note-taking and collaboration application with markdown support that integrates tasks, wikis, and databases. The company describes the app as an all-in-one workspace for note-taking, project management and task management. In addition to cross-platform apps, it can be accessed via most web browsers.
  * [Nuclino](https://www.nuclino.com) - A lightweight and collaborative wiki for all your team's knowledge, docs, and notes. Free plan with all essential features, up to 50 items, and 5GB storage.
  * [OnlineInterview.io](https://onlineinterview.io/) - Free code interview platform with embedded video chat, drawing board, and online code editor where you can compile and run your code on the browser. You can create a remote interview room with just one click.
  * [paste.sh](https://paste.sh/) — This is a JavaScript and the Crypto based simple paste site.
  * [Pastefy](https://pastefy.app/) - Beautiful and simple Pastebin with optional Client-Encryption, Multitab-Pastes, an API, a highlighted Editor and more.
  * [Pendulums](https://pendulums.io/) - Pendulums is a free time tracking tool that helps you manage your time in a better manner with an easy-to-use interface and valuable statistics.
  * [Proton Pass](https://proton.me/pass) — Password manager with built-in email aliases, 2FA authenticator, sharing and passkeys. Available on web, browser extension, and mobile app and desktop.
  * [Pullflow](https://pullflow.com) — Pullflow offers an AI-enhanced platform for code review collaboration across GitHub, Slack, and VS Code.
  * [Pumble](https://pumble.com) - Free team chat app. Unlimited users and message history, free forever.
  * [Quidlo Timesheets](https://www.quidlo.com/timesheets) - A simple timesheet and time tracking app for teams. The free plan has time tracking and generating reports features for up to 10 users.
  * [Raindrop.io](https://raindrop.io) - Private and secure bookmarking app for macOS, Windows, Android, iOS, and Web. Free Unlimited Bookmarks and Collaboration.
  * [Revolt.chat](https://revolt.chat/) — An OpenSource alternative for[Discord](https://discord.com/), that respects your privacy. It also have most proprietary features from discord for free. Revolt is a all in one application that is secure and fast, while being 100% free. every features are free. They also have (official & unofficial) plugins support unlike most main-stream chatting applications.
  * [Rocket.Chat](https://rocket.chat/) - Open-source communication platform with Omnichannel features, Matrix Federation, Bridge with others apps, Unlimited messaging, and Full messaging history.
  * [ruttl.com](https://ruttl.com/) — The best all-in-one feedback tool to collect digital feedback and review websites, PDFs, and images.
  * [Screen Sharing via Browser](https://screensharing.net) - Free screen sharing tool, share your screen with collabrators right from your browser, no download or registration needed. For free.
  * [seafile.com](https://www.seafile.com/) — Private or cloud storage, file sharing, sync, discussions. The cloud version has just 1 GB
  * [SiteDots](https://sitedots.com/) - Share feedback for website projects directly on your website, no emulation, canvas or workarounds. Completely functional free tier.
  * [Slab](https://slab.com/) — A modern knowledge management service for teams. Free for up to 10 users.
  * [slack.com](https://slack.com/) — Free for unlimited users with some feature limitations
  * [StatusPile](https://www.statuspile.com/) - A status page of status pages. Could you track the status pages of your upstream providers?
  * [Stickies](https://stickies.app/) - Visual collaboration app used for brainstorming, content curation, and notes. Free for up to 3 Walls, unlimited users, and 1 GB storage.
  * [StreamBackdrops](https://streambackdrops.com) — Free HD virtual backgrounds for video calls and team meetings. Professional backgrounds for Zoom, Teams, and Google Meet. No signup required, free for personal use.
  * [talky.io](https://talky.io/) — Free group video chat. Anonymous. Peer‑to‑peer. No plugins, signup, or payment required
  * [Teamcamp](https://www.teamcamp.app) - All-in-one project management application for software development companies.
  * [Teamhood](https://teamhood.com/) - Free Project, Task, and Issue-tracking software. Supports Kanban with Swimlanes and full Scrum implementation. Has integrated time tracking. Free for five users and three project portfolios.
  * [Teamplify](https://teamplify.com) - improve team development processes with Team Analytics and Smart Daily Standup. Includes full-featured Time Off management for remote-first teams. Free for small groups of up to 5 users.
  * [Telegram](https://telegram.org/) — Telegram is for everyone who wants fast, reliable messaging and calls. Business users and small teams may like the large groups, usernames, desktop apps, and powerful file-sharing options.
  * [Tencent RTC](https://trtc.io/) — Tencent Real-Time Communication (TRTC) offers solutions for group audio/video calls.10,000 free minutes/month for the first year.
  * [TimeCamp](https://www.timecamp.com/) - Free time tracking software for unlimited users. Easily integrates with PM tools like Jira, Trello, Asana, etc.
  * [tldraw.com](https://tldraw.com) —  Free open-source white-boarding and diagramming tool with intelligent arrows, snapping, sticky notes, and SVG export features. Multiplayer mode for collaborative editing. Free official VS Code extension available as well.
  * [transfernow](https://www.transfernow.net/) — simplest, fastest and safest interface to transfer and share files. Send photos, videos and other large files without a manditory subscription.
  * [Tugboat](https://tugboat.qa) - Preview every pull request, automated and on-demand. Free for all, complimentary Nano tier for non-profits.
  * [twist.com](https://twist.com) — An asynchronous-friendly team communication app where conversations stay organized and on-topic. Free and Unlimited plans are available. Discounts are provided for eligible teams.
  * [userforge.com](https://userforge.com/) - Interconnected online personas, user stories and context mapping.  Helps keep design and dev in sync free for up to 3 personas and two collaborators.
  * [Visual Debug](https://visualdebug.com) - A Visual feedback tool for better client-dev communication
  * [Webex](https://www.webex.com/) — Video meetings with a free plan offering 40 minutes per meeting with 100 attendees.
  * [Webvizio](https://webvizio.com) — Website feedback tool, website review software, and bug reporting tool for streamlining web development collaboration on tasks directly on live websites and web apps, images, PDFs, and design files.
  * [whereby.com](https://whereby.com/) — One-click video conversations, for free (formerly known as appear.in)
  * [windmill.dev](https://windmill.dev/) - Windmill is an open-source developer platform to quickly build production-grade multi-step automation and internal apps from minimal Python and Typescript scripts. As a free user, you can create and be a member of at most three non-premium workspaces.
  * [wistia.com](https://wistia.com/) — Video hosting with viewer analytics, HD video delivery, and marketing tools to help understand your visitors, 25 videos, and Wistia branded player
  * [wormhol.org](https://www.wormhol.org/) — Straightforward file sharing service. Share unlimited files up to 5GB with as many peers as you want.
  * [Wormhole](https://wormhole.app/) - Share files up to 5GB with end-to-end encryption for up to 24hours. For files larger than 5 GB, it uses peer-to-peer transfer to send your files directly.
  * [zoom.us](https://zoom.us/) — Secure Video and Web conferencing add-ons available. The free plan is limited to 40 minutes.
  * [Zulip](https://zulip.com/) — Real-time chat with a unique email-like threading model. The free plan includes 10,000 messages of search history and File storage up to 5 GB. also, it provides a self-hostable open-source version.

**[⬆️ Back to Top](#table-of-contents)**

## CMS

  * [Contentful](https://www.contentful.com/) — Headless CMS. Content management and delivery APIs in the cloud. Comes with one free Community space that includes five users, 25K records, 48 Content Types, 2 locales.
  * [Cosmic](https://www.cosmicjs.com/) — Headless CMS and API toolkit. Free personal plans for developers.
  * [Crystallize](https://crystallize.com) — Headless PIM with ecommerce support. Built-in GraphQL API. The free version includes unlimited users, 1000 catalog items, 5 GB/month bandwidth, and 25k/month API calls.
  * [DatoCMS](https://www.datocms.com/) - Offers free tier for small projects. DatoCMS is a GraphQL-based CMS. On the lower tier, you have 100k/month calls.
  * [Hygraph](https://hygraph.com/) - Offers free tier for small projects. GraphQL first API. Move away from legacy solutions to the GraphQL native Headless CMS - and deliver omnichannel content API first.
  * [Prismic](https://www.prismic.io/) — Headless CMS. Content management interface with fully hosted and scalable API. The Community Plan provides unlimited API calls, documents, custom types, assets, and locales to one user. Everything that you need for your next project. Bigger free plans are available for Open Content/Open Source projects.
  * [Sanity.io](https://www.sanity.io/) - Platform for structured content with an open-source editing environment and a real-time hosted data store. Unlimited projects. Unlimited admin users, three non-admin users, two datasets, 500K API CDN requests, 10GB bandwidth, and 5GB assets included for free per project.
  * [Solo](https://soloist.ai) - Free AI website creator from Mozilla, create a beautiful website for your business from a few simple inputs. Free custom domain, no credit card needed.
  * [Squidex](https://squidex.io/) - Offers free tier for small projects. API / GraphQL first. Open source and based on event sourcing (versing every change automatically).
  * [Storyblok](https://www.storyblok.com) - A Headless CMS for developers and marketers that works with all modern frameworks. The Community (free) tier offers Management API, Visual Editor, ten sources, Custom Field Types, Internationalization (unlimited languages/locales), Asset Manager (up to 2500 assets), Image Optimizing Service, Search Query, Webhook + 250GB Traffic/month included.
  * [TinaCMS](https://tina.io/) — Replacing Forestry.io. Open source Git-backed headless CMS that supports Markdown, MDX, and JSON. The basic offer is free with two users available.
  * [WPJack](https://wpjack.com) - Set up WordPress on any cloud in less than 5 minutes! The free tier includes 1 server, 2 sites, free SSL certificates, and unlimited cron jobs. No time limits or expirations—your website, your way.

**[⬆️ Back to Top](#table-of-contents)**

## Code Generation

* [Appinvento](https://appinvento.io/) — A free no-code app builder. It provides complete access to the automatically generated backend source code and allows for unlimited APIs and routes. The free plan includes three projects and five tables.
* [DhiWise](https://www.dhiwise.com/) — Converts Figma designs into dynamic Flutter and React applications. Its code generation technology is designed to optimize workflows for building production-ready mobile and web experiences.
* [Karbon Sites](https://www.karbonsites.space) — An AI-powered site builder and editor that generates production-ready frontend code from text prompts, sketches, or resumes. Features include native Android (APK) export and a free tier with 5 generations per month (unlimited via custom Gemini API key).
* [Metalama](https://www.postsharp.net/metalama) — A C#-specific tool that generates boilerplate code on the fly during compilation to keep source code clean. It is free for open-source projects; its commercial-friendly free tier includes up to three aspects.
* [Supermaven](https://www.supermaven.com/) — A high-speed AI code completion plugin for VS Code, JetBrains, and Neovim. The free tier provides unlimited inline completions with a focus on ultra-low latency.
* [v0.dev](https://v0.dev/) — Created by Vercel, v0 generates copy-and-paste friendly React code using shadcn/ui and Tailwind CSS. It uses a credit system, providing 1,200 starting credits and 200 free credits monthly.

**[⬆️ Back to Top](#table-of-contents)**

## Code Quality

  * [beanstalkapp.com](https://beanstalkapp.com/) — A complete workflow to write, review, and deploy code), a free account for one user, and one repository with 100 MB of storage
  * [codacy.com](https://www.codacy.com/) — Automated code reviews for PHP, Python, Ruby, Java, JavaScript, Scala, CSS, and CoffeeScript, free for unlimited public and private repositories
  * [Codeac.io](https://www.codeac.io/infrastructure-as-code.html?ref=free-for-dev) - Automated Infrastructure as Code review tool for DevOps integrates with GitHub, Bitbucket, and GitLab (even self-hosted). In addition to standard languages, it also analyzes Ansible, Terraform, CloudFormation, Kubernetes, and more. (open-source free)
  * [codecov.io](https://codecov.io/) — Code coverage tool (SaaS), free for Open Source and one free private repo
  * [CodeFactor](https://www.codefactor.io) — Automated Code Review for Git. The free version includes unlimited users, public repositories, and one private repo.
  * [coderabbit.ai](https://coderabbit.ai) — AI-powered code review tool that integrates with GitHub/GitLab. Free tier includes 200 files/hour, 3 reviews per hour, and 50 conversations/hour. Free forever for open source projects.
  * [CodSpeed](https://codspeed.io) - Automate performance tracking in your CI pipelines. Catch performance regressions before deployment, thanks to precise and consistent metrics. Free forever for Open Source projects.
  * [coveralls.io](https://coveralls.io/) — Display test coverage reports, free for Open Source
  * [deepscan.io](https://deepscan.io) — Advanced static analysis for automatically finding runtime errors in JavaScript code, free for Open Source
  * [DeepSource](https://deepsource.io/) - DeepSource continuously analyzes source code changes, finding and fixing issues categorized under security, performance, anti-patterns, bug-risks, documentation, and style. Native integration with GitHub, GitLab, and Bitbucket.
  * [DiffText](https://difftext.com) - Instantly find the differences between two blocks of code. Completely free to use.
  * [eversql.com](https://www.eversql.com/) — EverSQL - The #1 platform for database optimization. Gain critical insights into your database and SQL queries automatically.
  * [gerrithub.io](https://review.gerrithub.io/) — Gerrit code review for GitHub repositories for free
  * [goreportcard.com](https://goreportcard.com/) — Code Quality for Go projects, free for Open Source
  * [gtmetrix.com](https://gtmetrix.com/) — Reports and thorough recommendations to optimize websites
  * [holistic.dev](https://holistic.dev/) - The #1 static code analyzer for Postgresql optimization. Performance, security, and architect database issues automatic detection service
  * [houndci.com](https://houndci.com/) — Comments on GitHub commits about code quality, free for Open Source
  * [reviewable.io](https://reviewable.io/) — Code review for GitHub repositories, free for public or personal repos.
  * [scan.coverity.com](https://scan.coverity.com/) — Static code analysis for Java, C/C++, C# and JavaScript, free for Open Source
  * [scrutinizer-ci.com](https://scrutinizer-ci.com/) — Continuous inspection platform, free for Open Source
  * [semanticdiff.com](https://app.semanticdiff.com/) — Programming language aware diff for GitHub pull requests and commits, free for public repositories
  * [shields.io](https://shields.io) — Quality metadata badges for open source projects
  * [sonarcloud.io](https://sonarcloud.io) — Automated source code analysis for Java, JavaScript, C/C++, C#, VB.NET, PHP, Objective-C, Swift, Python, Groovy and even more languages, free for Open Source

**[⬆️ Back to Top](#table-of-contents)**

## Code Search and Browsing

  * [CodeKeep](https://codekeep.io) - Google Keep for Code Snippets. Organize, Discover, and share code snippets, featuring a powerful code screenshot tool with preset templates and a linking feature.
  * [libraries.io](https://libraries.io/) — Search and dependency update notifications for 32 different package managers, free for open source
  * [Namae](https://namae.dev/) - Search various websites like GitHub, Gitlab, Heroku, Netlify, and many more for the availability of your project name.
  * [tickgit.com](https://www.tickgit.com/) — Surfaces `TODO` comments (and other markers) to identify areas of code worth returning to for improvement.

**[⬆️ Back to Top](#table-of-contents)**

## CI and CD

  * [appcircle.io](https://appcircle.io) — An enterprise-grade mobile DevOps platform that automates the build, test, and publish store of mobile apps for faster, efficient release cycle. Free for 30 minutes max build time per build, 20 monthly builds and 1 concurrent build.
  * [appveyor.com](https://www.appveyor.com/) — CD service for Windows, free for Open Source
  * [bitrise.io](https://www.bitrise.io/) — A CI/CD for mobile apps, native or hybrid. With 200 free builds/month 10 min build time and two team members. OSS projects get 45 min build time, +1 concurrency and unlimited team size.
  * [buddy.works](https://buddy.works/) — A CI/CD with five free projects and one concurrent run (120 executions/month)
  * [Buildkite](https://buildkite.com) CI Pipelines free for 3 users and 5k job minutes/month. Test Analytics free developer tier includes 100k test executions/month, with more free inclusions for open-source projects.
  * [bytebase.com](https://www.bytebase.com/) — Database CI/CD and DevOps. Free under 20 users and ten database instances
  * [CircleCI](https://circleci.com/) — Comprehensive free plan with all features included in a hosted CI/CD service for GitHub, GitLab, and BitBucket repositories. Multiple resource classes, Docker, Windows, Mac OS, ARM executors, local runners, test splitting, Docker Layer Caching, and other advanced CI/CD features. Free for up to 6000 minutes/month execution time, unlimited collaborators, 30 parallel jobs in private projects, and up to 80,000 free build minutes for Open Source projects.
  * [cirrus-ci.org](https://cirrus-ci.org) - Free for public GitHub repositories
  * [cirun.io](https://cirun.io) - Free for public GitHub repositories
  * [codemagic.io](https://codemagic.io/) - Free 500 build minutes/month
  * [deployhq.com](https://www.deployhq.com/) — 1 project with ten daily deployments (30 build minutes/month)
  * [LocalOps](https://localops.co/) - Deploy your app on AWS/GCP/Azure in under 30 minutes. Setup standardised app environments on any cloud, which come with in-built continuous deployment automation and advanced observability. The free plan allows 1 user and 1 app environment.
  * [Make](https://www.make.com/en) — The workflow automation tool lets you connect apps and automate workflows using UI. It supports many apps and the most popular APIs. Free for public GitHub repositories, and free tier with 100 Mb, 1000 Operations, and 15 minutes of minimum interval.
  * [Mergify](https://mergify.com) — workflow automation and merge queue for GitHub — Free for public GitHub repositories
  * [Nx Cloud](https://nx.dev/ci) - Nx Cloud speeds up your monorepos on CI with features such as remote caching, distribution of tasks across machines and even automated splitting of your e2e test runs. It comes with a free plan for up to 30 contributors with generous 150k credits included.
  * [RunMyJob](https://runmyjob.io) - Run GitHub Actions and GitLab CI pipelines smarter with real-time scaling Spike Instances. Free tier includes 400 vCPU-minutes, 800 GB-minutes, and 10 concurrent jobs with high-performance runners (12 vCPU and 32 GB RAM per job).
  * [Shipfox](https://www.shipfox.io/) - Run your GitHub actions 2x faster, 3.000 build minutes free each month.
  * [Spacelift](https://spacelift.io/) - Management platform for Infrastructure as Code. Free plan features: IaC collaboration, Terraform module registry, ChatOps integration, Continuous resource compliance with Open Policy Agent, SSO with SAML 2.0, and access to public worker pools: up to 200 minutes/month
  * [Squash Labs](https://www.squash.io/) — creates a VM for each branch and makes your app available from a unique URL, Unlimited public & private repos, Up to 2 GB VM Sizes.
  * [Terramate](https://terramate.io/) - Terramate is an orchestration and management platform for Infrastructure as Code (IaC) tools such as Terraform, OpenTofu, and Terragrunt. Free up to 2 users including all features.
  * [Terrateam](https://terrateam.io) - GitOps-first Terraform automation with pull request-driven workflows, project isolation via self-hosted runners, and layered runs for ordered operations. Free for up to 3 users.

**[⬆️ Back to Top](#table-of-contents)**

## Testing

  * [Appetize](https://appetize.io) — Test your Android & iOS apps on this Cloud Based Android Phone / Tablets emulator and iPhone/iPad simulators directly in your browser. The free tier includes two concurrent session with 30 minutes of usage per month. No limit on app size.
  * [Argos](https://argos-ci.com) - Open Source visual testing for developers. Unlimitedprojects, with 5,000 screenshots per month. Free for open-source projects.
  * [Bencher](https://bencher.dev/) - A continuous benchmarking tool suite to catch CI performance regressions. Free for all public projects.
  * [BugBug](https://bugbug.io/) - Lightweight test automation tool for web applications. It is easy to learn and doesn't require coding. You can run unlimited tests on your own computer for free. You also get cloud monitoring and CI/CD integration for an additional monthly fee.
  * [checkbot.io](https://www.checkbot.io/) — Browser extension that tests if your website follows 50+ SEO, speed and security best practices. Free tier for smaller websites.
  * [Checkly](https://checklyhq.com) - Code-first synthetic monitoring for modern DevOps. Monitor your APIs and apps at a fraction of the price of legacy providers. Powered by a Monitoring as Code workflow and Playwright. Generous free tier for devs.
  * [CORS-Tester](https://cors-error.dev/cors-tester/) - A free tool for developers and API testers to check if an API is CORS-enabled for a given domain and identify gaps. Get actionable insights.
  * [cypress.io](https://www.cypress.io/) - Fast, easy and reliable testing for anything that runs in a browser. Cypress Test Runner is always free and open-source with no restrictions and limitations. Cypress Dashboard is free for open-source projects for up to 5 users.
  * [everystep-automation.com](https://www.everystep-automation.com/) — Records and replays all steps made in a web browser and creates scripts, free with fewer options
  * [gridlastic.com](https://www.gridlastic.com/) — Selenium Grid testing with a free plan of up to 4 simultaneous selenium nodes/10 grid starts/4,000 test minutes/month
  * [katalon.com](https://katalon.com) - Provides a testing platform that can help teams of all sizes at different levels of testing maturity, including  Katalon Studio, TestOps (+ Visual Testing free), TestCloud, and Katalon Recorder.
  * [Keploy](https://keploy.io/) - Keploy is a functional testing toolkit for developers. Recording API calls generates E2E tests for APIs (KTests) and mocks or stubs(KMocks). It is free for Open Source projects.
  * [loadmill.com](https://www.loadmill.com/) - Automatically create API and load tests by analyzing network traffic. Simulate up to 50 concurrent users for up to 60 minutes for free monthly.
  * [lost-pixel.com](https://lost-pixel.com) - holistic visual regression testing for your Storybook, Ladle, Histoire stories and Web Apps. Unlimited team members, totally free for open-source, 7,000 snapshots/month.
  * [pagegym.com](https://pagegym.com) - Load behvariour and page speed analysis and optimization tool. The free plan provides 10 tests per day, 5 experiments per week, and 15 GB of maximum ingested data per month.
  * [percy.io](https://percy.io) - Add visual testing to any web app, static site, style guide, or component library.  Unlimited team members, Demo app, and unlimited projects, 5,000 snapshots/month.
  * [qase.io](https://qase.io) - Test management system for Dev and QA teams. Manage test cases, compose test runs, perform tests, track defects, and measure impact. The free tier includes all core features, with 500MB available for attachments and up to 3 users.
  * [Repeato](https://repeato.app/) No-code mobile app test automation tool built on top of computer vision and AI. Works for native apps, flutter, react-native, web, ionic, and many more app frameworks. The free plan is limited to 10 tests for iOS and 10 for Android, but includes most of the features of the paid plans, including unlimited test runs.
  * [Requestly](https://requestly.com/) Open-source Chrome Extension to Intercept, Redirect and Mock HTTP Requests. Featuring [Debugger](https://requestly.com/products/web-debugger/), [Mock Server](https://requestly.com/products/mock-server/), [API Client](https://requestly.com/products/api-client/) and [Session Recording](https://requestly.com/products/session-book/).  Redirect URLs, Modify HTTP Headers, Mock APIs, Inject custom JS, Modify GraphQL Requests, Generate Mock API Endpoints, Record session with Network & Console Logs. Create upto 10 rules in Free Tier. Free for open-source.
  * [seotest.me](https://seotest.me/) — Free on-page SEO website tester. 10 free website crawls per day. Useful SEO learning resources and recommendations on how to improve the on-page SEO results for any website regardless of technology.
  * [snippets.uilicious.com](https://snippets.uilicious.com) - It's like CodePen but for cross-browser testing. UI-licious lets you write tests like user stories and offers a free platform - UI-licious Snippets - that allows you to run unlimited tests on Chrome with no sign-up required for up to 3 minutes per test run. Found a bug? You can copy the unique URL to your test to show your devs exactly how to reproduce the bug.
  * [SSR (Server-side Rendering) Checker](https://www.crawlably.com/ssr-checker/) - Check SSR (server-side rendering) for any URL by visually comparing the server rendered version of the page with the regular version.
  * [testingbot.com](https://testingbot.com/) — Selenium Browser and Device Testing, [free for Open Source](https://testingbot.com/open-source)
  * [Testspace.com](https://testspace.com/) - A Dashboard for publishing automated test results and a Framework for implementing manual tests as code using GitHub. The service is [free for Open Source](https://github.com/marketplace/testspace-com) and accounts for 450 monthly results.
  * [tesults.com](https://www.tesults.com) — Test results reporting and test case management. Integrates with popular test frameworks. Open Source software developers, individuals, educators, and small teams getting started can request discounted and free offerings beyond basic free projects.
  * [UseWebhook.com](https://usewebhook.com) - Capture and inspect webhooks from your browser. Forward to localhost, or replay from history. Free to use.
  * [Vaadin](https://vaadin.com) — Build scalable UIs in Java or TypeScript, and use the integrated tooling, components, and design system to iterate faster, design better, and simplify the development process. Unlimited Projects with five years of free maintenance.
  * [webhook-test.com](https://webhook-test.com) - Debug and inspect webhooks and HTTP requests with a unique URL during integration. Completely free, you can create unlimited URLs and receive recommendations.
  * [webhook.site](https://webhook.site) - Verify webhooks, outbound HTTP requests, or emails with a custom URL. A temporary URL and email address are always free.
  * [websitepulse.com](https://www.websitepulse.com/tools/) — Various free network and server tools.
  * [kogiQA](https://kogiqa.com) — A web UI automation tool that functions without the need for selectors. Every developer gets 500 actions per month for free.

**[⬆️ Back to Top](#table-of-contents)**

## Security and PKI

  * [aikido.dev](https://www.aikido.dev) — All-in-one appsec platform covering SCA, SAST, CSPM, DAST, Secrets, IaC, Malware, Container scanning, EOL,... Free plan includes two users, scanning of 10 repos, 1 cloud, 2 containers & 1 domain.
  * [CertKit](https://www.certkit.io/certificate-management) - Manage SSL Certificate issuance, renewal, and monitoring. Search the Certificate Transparency Logs. Free for 3 certificates and 1 user after the beta.
  * [Corgea](https://corgea.com/) - Free autonomous security platform that finds, validates and fixes insecure code and packages across +20 languages and frameworks. Free plan includes 1 user and 2 repos. 
  * [crypteron.com](https://www.crypteron.com/) — Cloud-first, developer-friendly security platform prevents data breaches in .NET and Java applications
  * [CyberChef](https://gchq.github.io/CyberChef/) — A simple, intuitive web app for analyzing and decoding/encoding data without dealing with complex tools or programming languages. Like a Swiss army knife of cryptography & encryption. All features are free to use, with no limit. Open source if you wish to self-host.
  * [Datree](https://www.datree.io/) — Open Source CLI tool to prevent Kubernetes misconfigurations by ensuring that manifests and Helm charts follow best practices as well as your organization’s policies
  * [Dependabot](https://dependabot.com/) Automated dependency updates for Ruby, JavaScript, Python, PHP, Elixir, Rust, Java (Maven and Gradle), .NET, Go, Elm, Docker, Terraform, Git Submodules, and GitHub Actions.
  * [DJ Checkup](https://djcheckup.com) — Scan your Django site for security flaws with this free, automated checkup tool. Forked from the Pony Checkup site.
  * [Doppler](https://doppler.com/) — Universal Secrets Manager for application secrets and config, with support for syncing to various cloud providers. Free for five users with basic access controls.
  * [Dotenv](https://dotenv.org/) — Sync your .env files, quickly & securely. Stop sharing your .env files over insecure channels like Slack and email, and never lose an important .env file again. Free for up to 3 teammates.
  * [GitGuardian](https://www.gitguardian.com) — Keep secrets out of your source code with automated secrets detection and remediation. Scan your git repos for 350+ types of secrets and sensitive files – Free for individuals and teams of 25 developers or less.
  * [HasMySecretLeaked](https://gitguardian.com/hasmysecretleaked) - Search across 20 million exposed secrets in public GitHub repositories, gists, issues,and comments for Free
  * [Have I been pwned?](https://haveibeenpwned.com) — REST API for fetching the information on the breaches.
  * [hostedscan.com](https://hostedscan.com) — Online vulnerability scanner for web applications, servers, and networks. Ten free scans per month.
  * [Infisical](https://infisical.com/) — Open source platform that lets you manage developer secrets across your team and infrastructure: everywhere from local development to staging/production 3rd-party services. Free for up to 5 developers.
  * [Internet.nl](https://internet.nl) — Test for modern Internet Standards like IPv6, DNSSEC, HTTPS, DMARC, STARTTLS and DANE
  * [letsencrypt.org](https://letsencrypt.org/) — Free SSL Certificate Authority with certs trusted by all major browsers
  * [meterian.io](https://www.meterian.io/) - Monitor Java, Javascript, .NET, Scala, Ruby, and NodeJS projects for security vulnerabilities in dependencies. Free for one private project, unlimited projects for open source.
  * [Mozilla Observatory](https://observatory.mozilla.org/) — Find and fix security vulnerabilities in your site.
  * [Project Gatekeeper](https://gatekeeper.binarybiology.top/) - An All-in-One SSL Toolkit Offering various features like Private Key & CSR Generator, SSL Certificate Decoder, Certificate Matcher and Order SSL Certificate. We offer the users to generate Free SSL Certificates from Let's Encrypt, Google Trust and BuyPass using CNAME Records rather than TXT Records.
  * [Protectumus](https://protectumus.com) - Free website security check, site antivirus, and server firewall (WAF) for PHP. Email notifications for registered users in the free tier.
  * [Public Cloud Threat Intelligence](https://cloudintel.himanshuanand.com/) — High confidence Indicator of Compromise(IOC) targeting public cloud infrastructure, A portion is available on github (https://github.com/unknownhad/AWSAttacks). Full list is available via API
  * [pyup.io](https://pyup.io) — Monitor Python dependencies for security vulnerabilities and update them automatically. Free for one private project, unlimited projects for open source.
  * [qualys.com](https://www.qualys.com/community-edition) — Find web app vulnerabilities, audit for OWASP Risks
  * [Socket](https://socket.dev) — Free supply chain security for individual developers, small teams, and open source projects. Includes a free app and firewall CLI tool to protect your code from vulnerable and malicious dependencies. Detects 70+ indicators of supply chain risk.
  * [SOOS](https://soos.io) - Free, unlimited SCA scans for open-source projects. Detect and fix security threats before release. Protect your projects with a simple and effective solution.
  * [ssllabs.com](https://www.ssllabs.com/ssltest/) — Intense analysis of the configuration of any SSL web server
  * [Sucuri SiteCheck](https://sitecheck.sucuri.net) - Free website security check and malware scanner
  * [TestTLS.com](https://testtls.com) - Test an SSL/TLS service for secure server configuration, certificates, chains, etc. Not limited to HTTPS.
  * [Virgil Security](https://virgilsecurity.com/) — Tools and services for implementing end-to-end encryption, database protection, IoT security, and more in your digital solution. Free for applications with up to 250 users.

**[⬆️ Back to Top](#table-of-contents)**

## Authentication, Authorization, and User Management

  * [360username](https://360username.com/) - A free tool to search a username across 90+ social platforms to find matching profiles.
  * [Aserto](https://www.aserto.com) - Fine-grained authorization as a service for applications and APIs. Free up to 1000 MAUs and 100 authorizer instances.
  * [asgardeo.io](https://wso2.com/asgardeo) - Seamless Integration of SSO, MFA, passwordless auth and more. Includes SDKs for frontend and backend apps. Free up to 1000 MAUs and five identity providers.
  * [Auth0](https://auth0.com/) — Hosted SSO. The free plan includes 25,000 MAUs, unlimited Social Connections, a custom domain, and more.
  * [Authgear](https://www.authgear.com) - Bring Passwordless, OTPs, 2FA, SSO to your apps in minutes. All Front-end included. Free up to 5000 MAUs.
  * [Authress](https://authress.io/) — Authentication login and access control, unlimited identity providers for any project. Facebook, Google, Twitter and more. The first 1000 API calls are free.
  * [Authy](https://authy.com) - Two-factor authentication (2FA) on multiple devices, with backups. Drop-in replacement for Google Authenticator. Free for up to 100 successful authentications.
  * [Cerbos Hub](https://www.cerbos.dev/product-cerbos-hub) - A complete authorization management system for authoring, testing, and deploying access policies. Fine-grained authorization and access control, free up to 100 monthly active principals.
  * [Clerk](https://clerk.com) — User management, authentication, 2FA/MFA, prebuilt UI components for sign-in, sign-up, user profiles, and more. Free up to 10,000 monthly active users.
  * [Cloud-IAM](https://www.cloud-iam.com/) — Keycloak Identity and Access Management as a Service. Free up to 100 users and one realm.
  * [Descope](https://www.descope.com/) — Highly customizable AuthN flows, has both a no-code and API/SDK approach, Free 7,500 active users/month, 50 tenants (up to 5 SAML/SSO tenants).
  * [duo.com](https://duo.com/) — Two-factor authentication (2FA) for website or app. Free for ten users, all authentication methods, unlimited, integrations, hardware tokens.
  * [Kinde](https://kinde.com/) - Simple, robust authentication you can integrate with your product in minutes.  Everything you need to get started with 7,500 free MAU.
  * [logintc.com](https://www.logintc.com/) — Two-factor authentication (2FA) by push notifications, free for ten users, VPN, Websites, and SSH
  * [Logto](https://logto.io/) - Develop, secure, and manage user identities of your product - for both authentication and authorization. Free for up to 5,000 MAUs with open-source self-hosted option available.
  * [MojoAuth](https://mojoauth.com/) - MojoAuth makes it easy to implement Passwordless authentication on your web, mobile, or any application in minutes.
  * [Okta](https://developer.okta.com/signup/) — User management, authentication and authorization. Free for up to 100 monthly active users.
  * [Ory](https://ory.sh/) - AuthN/AuthZ/OAuth2.0/Zero Trust managed security platform. Forever free developer accounts with all security features, unlimited team members, 200 daily active users, and 25k/mo permission checks.
  * [Permit.io](https://permit.io) - Auhtorization-as-a-service provider platform enabling RBAC, ABAC, and ReBAC for scalable microservices with real-time updates and a no-code policy UI. A 1000 Monthly Active User free tier.
  * [Phase Two](https://phasetwo.io) - Keycloak Open Source Identity and Access Management. Free realm up to 1000 users, up to 10 SSO connections, leveraging Phase Two's Keycloak enhanced container which includes the [Organization](https://phasetwo.io/product/organizations/) extension.
  * [PropelAuth](https://propelauth.com) — A Sell to companies of any size immediately with a few lines of code, free up to 200 users and 10k Transactional Emails (with a watermark branding: "Powered by PropelAuth").
  * [Stack Auth](https://stack-auth.com) — Open-source authentication that doesn't suck. The most developer-friendly solution, getting you started in just five minutes. Self-hostable for free, or offers a managed SaaS version with 10k free Monthly Active Users.
  * [Stytch](https://www.stytch.com/) - An all-in-one platform that provides APIs and SDKs for authentication and fraud prevention. The free plan includes 10,000 monthly active users, unlimited organizations, 5 SSO or SCIM connections, and 1,000 M2M tokens.
  * [SuperTokens](https://supertokens.com/) - Open source user authentication that natively integrates into your app - enabling you to get started quickly while controlling the user and developer experience. Free for up to 5000 MAUs.
  * [WorkOS](https://workos.com/) - Free user management and authentication for up to 1 Million MAUs. Support email + password, social auth, Magic Auth, MFA, and more.
  * [ZITADEL Cloud](https://zitadel.com) — A turnkey user and access management that works for you and supports multi-tenant (B2B) use cases. Free for up to 25,000 authenticated requests, with all security features (no paywall for OTP, Passwordless, Policies, and so on).


**[⬆️ Back to Top](#table-of-contents)**

## Mobile App Distribution and Feedback

  * [Appho.st](https://appho.st) - Mobile app hosting platform. The free plan includes five apps, 50 monthly downloads, and a maximum file size of 100 MB.
  * [Diawi](https://www.diawi.com) - Deploy iOS & Android apps directly to devices. Free plan: app uploads, password-protected links, 1-day expiration, ten installations.
  * [GetUpdraft](https://www.getupdraft.com) - Distribute mobile apps for testing. The free plan includes one app project, three app versions, 500 MB storage, and 100 app installations per month.
  * [InstallOnAir](https://www.installonair.com) - Distribute iOS & Android apps over the air. Free plan: unlimited uploads, private links, 2-day expiration for guests, 60 days for registered users.
  * [Loadly](https://loadly.io) - iOS & Android beta apps distribution service offers completely free services with unlimited downloads, high-speed downloads, and unlimited uploads.

**[⬆️ Back to Top](#table-of-contents)**

## Management System

  * [bitnami.com](https://bitnami.com/) — Deploy prepared apps on IaaS. Management of 1 AWS micro instance free
  * [Esper](https://esper.io) — MDM and MAM for Android Devices with DevOps. One hundred devices free with one user license and 25 MB Application Storage.
  * [jamf.com](https://www.jamf.com/) —  Device management for iPads, iPhones, and Macs, three devices free
  * [Miradore](https://miradore.com) — Device Management service. Stay up-to-date with your device fleet and secure unlimited devices for free. The free plan offers basic features.
  * [moss.sh](https://moss.sh) - Help developers deploy and manage their web apps and servers. Free up to 25 git deployments per month
  * [ploi.io](https://ploi.io/) - Server management tool to easily manage and deploy your servers & sites. Free for one server.
  * [runcloud.io](https://runcloud.io/) - Server management focusing mainly on PHP projects. Free for up to 1 server.
  * [serveravatar.com](https://serveravatar.com) — Manage and monitor PHP-based web servers with automated configurations. Free for one server.
  * [xcloud.host](https://xcloud.host) — Server management and deployment platform with a user-friendly interface. Free tier available for one server.

**[⬆️ Back to Top](#table-of-contents)**

## Messaging and Streaming

  * [Ably](https://www.ably.com/) - Realtime messaging service with presence, persistence and guaranteed delivery. The free plan includes 3m messages per month, 100 peak connections, and 100 peak channels.
  * [cloudamqp.com](https://www.cloudamqp.com/) — RabbitMQ as a Service. Little Lemur plan: max 1 million messages/month, max 20 concurrent connections, max 100 queues, max 10,000 queued messages, multiple nodes in different AZ's
  * [courier.com](https://www.courier.com/) — Single API for push, in-app, email, chat, SMS, and other messaging channels with template management and other features. The free plan includes 10,000 messages/mo.
  * [EMQX Serverless](https://www.emqx.com/en/cloud/serverless-mqtt) - Scalable and secure serverless MQTT broker you can get in seconds. 1M session minutes/month free forever (no credit card required).
  * [Engage](https://engage.so/) - All-in-one Customer Engagement and Automation Tool (email, push, SMS, product tours, banners and more) for SaaS. Free for up to 1,000 active users per month.
  * [engagespot.co](https://engagespot.co/) — Multi-channel notification infrastructure for developers with a prebuilt in-app inbox and no-code template editor. Free plan includes 10,000 messages/mo.
  * [HiveMQ](https://www.hivemq.com/mqtt-cloud-broker/) - Connect your MQTT devices to the Cloud Native IoT Messaging Broker.  Free to connect up to 100 devices (no credit card required) forever.
  * [httpSMS](https://httpsms.com) - Send and receive text messages using your Android phone as an SMS Gateway. Free to send and receive up to 200 messages per month.
  * [knock.app](https://knock.app) – Notifications infrastructure for developers. Send to multiple channels like in-app, email, SMS, Slack, and push with a single API call. The free plan includes 10,000 messages/mo.
  * [NotificationAPI.com](https://www.notificationapi.com/) — Add user notifications to any software in 5 minutes. The free plan includes 10,000 notifications/month + 100 SMS and Automated Calls.
  * [Novu.co](https://novu.co) — The open-source notification infrastructure for developers. Simple components and APIs for managing all communication channels in one place: Email, SMS, Direct, In-App and Push. The free plan includes 30,000 notifications/month with 90 days of retention.
  * [Pocket Alert](https://pocketalert.app) - Send push notifications to your iOS and Android devices. Effortlessly integrate via API or Webhooks and maintain full control over your alerts. Free plan: 50 messages per day to 1 device and 1 application.
  * [pubnub.com](https://www.pubnub.com/) - Swift, Kotlin, and React messaging at 1 million transactions each month. Transactions may contain multiple messages.
  * [pusher.com](https://pusher.com/) — Realtime messaging service. Free for up to 100 simultaneous connections and 200,000 messages/day
  * [scaledrone.com](https://www.scaledrone.com/) — Realtime messaging service. Free for up to 20 simultaneous connections and 100,000 events/day
  * [SMSGate](https://sms-gate.app) - SMS Gateway for Android™ enables sending and receiving SMS messages through your devices using cloud routing. Completely free cloud service (with recommended notification for usage above 10,000 messages/day to maintain quality for all users).
  * [SuprSend](https://www.suprsend.com/) - SuprSend is a notification infrastructure that streamlines your product notifications with an API-first approach. Create and deliver transactional, crons, and engagement notifications on multiple channels with a single notification API. In free plan you get 10,000 notifications per month, including different workflow nodes such as digests, batches, multi-channels, preferences, tenants, broadcasts and more.
  * [synadia.com](https://synadia.com/ngs) — [NATS.io](https://nats.io) as a service. Global, AWS, GCP, and Azure. Free forever with 4k msg size, 50 active connections, and 5GB of data per month.
  * [webpushr](https://www.webpushr.com/) - Web Push Notifications - Free for upto 10k subscribers, unlimited push notifications, in-browser messaging

**[⬆️ Back to Top](#table-of-contents)**

## Log Management

  * [bugfender.com](https://bugfender.com/) — Free up to 100k log lines/day with 24 hours retention
  * [log.dog](https://log.dog/) — LogDog is a remote debugging/logging SDK (iOS and Android) with a web ui. Captures all logs, requests and events in real-time and allows to intercept them. Free for up to 100MB of logs every month
  * [logflare.app](https://logflare.app/) — Free for up to 12,960,000 entries per app per month, 3 days retention
  * [logtail.com](https://logtail.com/) — ClickHouse-based SQL-compatible log management. Free up to 1 GB per month, three days retention.
  * [logzab.com](https://logzab.com/) — Audit trail management system. Free 1,000 user activity logs per month, 1-month retention, for up to 5 projects.
  * [ManageEngine Log360 Cloud](https://www.manageengine.com/cloud-siem/) — Log Management service powered by Manage Engine. Free Plan offers 50 GB storage with 15 days Storage Retention and 7 days search.
  * [openobserve.ai](https://openobserve.ai/) - 200 GB Ingestion/month free, 15 Days Retention

**[⬆️ Back to Top](#table-of-contents)**

## Translation Management

  * [AutoLocalise.com](https://www.autolocalise.com/) — Instantly localize without managing translation files. Free for up to 10,000 characters/month, unlimited languages.
  * [crowdin.com](https://crowdin.com/) — Unlimited projects, unlimited strings, and collaborators for Open Source
  * [Free PO editor](https://pofile.net/free-po-editor) — Free for everybody
  * [Lingo.dev](https://lingo.dev) – Open-source AI-powered CLI for web & mobile localization. Bring your own LLM, or use 10,000 free words every month via Lingo.dev-managed localization engine.
  * [lingohub.com](https://lingohub.com/) — Free up to 3 users, always free for Open Source
  * [localazy.com](https://localazy.com) - Free for 1000 source language strings, unlimited languages, unlimited contributors, startup and open source deals
  * [Localit](https://localit.io) – Fast, developer-friendly localization platform with seamless and free GitHub/GitLab integration, AI-assisted and manual translations, and a generous free plan (includes 2 users, 500 keys, and unlimited projects).
  * [localizely.com](https://localizely.com/) — Free for Open Source
  * [Loco](https://localise.biz/) — Free up to 2000 translations, Unlimited translators, ten languages/project, 1000 translatable assets/project
  * [POEditor](https://poeditor.com/) — Free up to 1000 strings
  * [SimpleLocalize](https://simplelocalize.io/) - Free up to 100 translation keys, unlimited strings, unlimited languages, startup deals
  * [Texterify](https://texterify.com/) - Free for a single user
  * [Tolgee](https://tolgee.io) - Free SaaS offering with limited translations, forever-free self-hosted version
  * [transifex.com](https://www.transifex.com/) — Free for Open Source

**[⬆️ Back to Top](#table-of-contents)**

## Monitoring

  * [assertible.com](https://assertible.com) — Automated API testing and monitoring. Free plans for teams and individuals.
  * [Better Stack](https://betterstack.com/better-uptime) - Uptime monitoring, incident management, on-call scheduling/alerting, and status pages in a single product. The free plan includes ten monitors with 3-minute check frequency and status pages.
  * [bleemeo.com](https://bleemeo.com) - Free for 3 servers, 5 uptime monitors, unlimited users, unlimited dashboards, unlimited alerting rules.
  * [checklyhq.com](https://checklyhq.com) - Open source E2E / Synthetic monitoring and deep API monitoring for developers. Free plan with one user and 10k API & network / 1.5k browser check runs.
  * [Core Web Vitals History](https://punits.dev/core-web-vitals-historical/) - Find Core Web Vitals history for a url or a website.
  * [cronitor.io](https://cronitor.io/) - Performance insights and uptime monitoring for cron jobs, websites, APIs and more. A free tier with five monitors.
  * [datadoghq.com](https://www.datadoghq.com/) — Free for up to 5 nodes
  * [deadmanssnitch.com](https://deadmanssnitch.com/) — Monitoring for cron jobs. One free snitch (monitor), more if you refer others to sign up
  * [downtimemonkey.com](https://downtimemonkey.com/) — 60 uptime monitors, 5-minute interval. Email, Slack alerts.
  * [economize.cloud](https://economize.cloud) — Economize helps demystify cloud infrastructure costs by organizing cloud resources to optimize and report the same. Free for up to $5,000 spent on Google Cloud Platform every month.
  * [fivenines.io](https://fivenines.io/) — Linux server monitoring with real‑time dashboards and alerting — free forever for up to 5 monitored servers at 60-seconds interval. No credit card required.
  * [Grafana Cloud](https://grafana.com/products/cloud/) - Grafana Cloud is a composable observability platform that integrates metrics and logs with Grafana. Free: 3 users, ten dashboards, 100 alerts, metrics storage in Prometheus and Graphite (10,000 series, 14 days retention), logs storage in Loki (50 GB of logs, 14 days retention)
  * [healthchecks.io](https://healthchecks.io) — Monitor your cron jobs and background tasks. Free for up to 20 checks.
  * [incidenthub.cloud](https://incidenthub.cloud/) — Cloud and SaaS status page aggregator - 20 monitors and 2 notification channels (Slack and Discord) are free forever.
  * [inspector.dev](https://www.inspector.dev) - A complete Real-Time monitoring dashboard in less than one minute with a free forever tier.
  * [instatus.com](https://instatus.com) - Get a beautiful status page in 10 seconds. Free forever with unlimited subs and unlimited teams.
  * [linkok.com](https://linkok.com) - Online broken link checker, free for small websites up to 100 pages, completely free for open-source projects.
  * [loader.io](https://loader.io/) — Free load testing tools with limitations
  * [Middleware.io](https://middleware.io/) -  Middleware observability platform provides complete visibility into your apps & stack, so you can monitor & diagnose issues at scale. They have a free forever plan for Dev community use that allows Log monitoring for up to 1M log events, Infrastructure monitoring & APM for up to 2 hosts.
  * [MonitorMonk](https://monitormonk.com) - Minimalist uptime monitoring with beautiful status pages. The Forever Free plan offers HTTPS, Keyword, SSL and Response-time monitorming for 10 websites or api-endpoints, and provides 2 dashboards/status pages.
  * [netdata.cloud](https://www.netdata.cloud/) — Netdata is an open-source tool to collect real-time metrics. It's a growing product and can also be found on GitHub!
  * [newrelic.com](https://www.newrelic.com) — New Relic observability platform built to help engineers create more perfect software. From monoliths to serverless, you can instrument everything and then analyze, troubleshoot, and optimize your entire software stack. The free tier offers 100GB/month of free data ingest, one free full-access user, and unlimited free primary users.
  * [OnlineOrNot.com](https://onlineornot.com/) - OnlineOrNot provides uptime monitoring for websites and APIs, monitoring for cron jobs and scheduled tasks. Also provides status pages. The first five checks with a 3-minute interval are free. The free tier sends alerts via Slack, Discord, and Email.
  * [OntarioNet.ca CN Test](https://cntest.ontarionet.ca) — Check if a website is blocked in China by the Great Firewall. It identifies DNS pollution by comparing DNS results and ASN information detected by servers in China versus servers in the United States.
  * [pagecrawl.io](https://pagecrawl.io/) -  Monitor website changes, free for up to 6 monitors with daily checks.
  * [pagertree.com](https://pagertree.com/) - Simple interface for alerting and on-call management. Free up to 5 users.
  * [phare.io](https://phare.io/) - Uptime Monitoring free for up to 100,000 events for unlimited projets and unlimited status pages.
  * [pingbreak.com](https://pingbreak.com/) — Modern uptime monitoring service. Check unlimited URLs and get downtime notifications via Discord, Slack, or email.
  * [Pingmeter.com](https://pingmeter.com/) - 5 uptime monitors with 10-minute interval. Monitor SSH, HTTP, HTTPS, and any custom TCP ports.
  * [pingpong.one](https://pingpong.one/) — Advanced status page platform with monitoring. The free tier includes one public customizable status page with an SSL subdomain. Pro plan is offered to open-source projects and non-profits free of charge.
  * [Pulsetic](https://pulsetic.com) - 10 monitors, 6 Months of historical Uptime/Logs, unlimited status pages, and custom domains included! For infinite time and unlimited email alerts for free. You don't need a credit card.
  * [robusta.dev](https://home.robusta.dev/) — Powerful Kubernetes monitoring based on Prometheus. Bring your own Prometheus or install the all-in-one bundle. The free tier includes up to 20 Kubernetes nodes. Alerts via Slack, Microsoft Teams, Discord, and more. Integrations with PagerDuty, OpsGenie, VictorOps, DataDog, and many other tools.
  * [Servervana](https://servervana.com) - Advanced uptime monitoring with support for large projects and teams. Provides HTTP monitoring, Browser based monitoring, DNS monitoring, domain monitoring, status pages and more. The free tier includes 10 HTTP monitors, 1 DNS monitor and one status page.
  * [Simple Observability](https://simpleobservability.com) — Powerful server monitoring in a unified platform for metrics and logs, with no setup complexity. Free for one server.
  * [sitesure.net](https://sitesure.net) - Website and cron monitoring - 2 monitors free
  * [skylight.io](https://www.skylight.io/) — Free for first 100,000 requests (Rails only)
  * [stathat.com](https://www.stathat.com/) — Get started with ten stats for free, no expiration
  * [statuscake.com](https://www.statuscake.com/) — Website monitoring, unlimited tests free with limitations
  * [statusgator.com](https://statusgator.com/) — Status page monitoring, 3 monitors free
  * [SweetUptime](https://dicloud.net/sweetuptime-server-uptime-monitoring/) — Server monitoring, uptime monitoring, DNS & domain monitoring. Monitor 10 server, 10 uptime, and 10 domain for free.
  * [syagent.com](https://syagent.com/) — Noncommercial free server monitoring service, alerts and metrics.
  * [UptimeObserver.com](https://uptimeobserver.com) - Get 20 uptime monitors with 5-minute intervals and a customizable status page—even for commercial use. Enjoy unlimited, real-time notifications via email and Telegram. No credit card needed to get started.
  * [uptimetoolbox.com](https://uptimetoolbox.com/) — Free monitoring for five websites, 60-second intervals, public statuspage.
  * [Wachete](https://www.wachete.com) - monitor five pages, checks every 24 hours.
  * [Xitoring.com](https://xitoring.com/) — Uptime monitoring: 20 free, Linux and Windows Server monitoring: 5 free, Status page: 1 free - Mobile app, multiple notification channel, and much more!

**[⬆️ Back to Top](#table-of-contents)**

## Crash and Exception Handling

  * [Axiom](https://axiom.co/) — Store up to 0.5 TB of logs with 30-day retention. Includes integrations with platforms like Vercel and advanced data querying with email/Discord notifiers.
  * [Bugsink](https://www.bugsink.com/) — Error-tracking with Sentry-SDK compatability. Free for up to 5,000 errors/month, or unlimited use when self-hosted.
  * [bugsnag.com](https://www.bugsnag.com/) — Free for up to 2,000 errors/month after the initial trial
  * [CatchJS.com](https://catchjs.com/) - JavaScript error tracking with screenshots and click trails. Free for open-source projects.
  * [elmah.io](https://elmah.io/) — Error logging and uptime monitoring for web developers. Free Small Business subscription for open-source projects.
  * [Embrace](https://embrace.io/) — Mobile app monitoring. Free for small teams with up to 1 million user sessions per year.
  * [exceptionless](https://exceptionless.com) — Real-time error, feature, log reporting, and more. Free for 3k events per month/1 user. Open source and easy to self-host for unlimited use.
  * [GlitchTip](https://glitchtip.com/) — Simple, open-source error tracking. Compatible with open-source Sentry SDKs. 1000 events per month for free, or can self-host with no limits
  * [honeybadger.io](https://www.honeybadger.io) - Exception, uptime, and cron monitoring. Free for small teams and open-source projects (12,000 errors/month).
  * [Jam](https://jam.dev) - Developer friendly bug reports in one click. Free plan with unlimited jams.
  * [memfault.com](https://memfault.com) — Cloud device observability and debugging platform. 100 devices free for [Nordic](https://app.memfault.com/register-nordic), [NXP](https://app.memfault.com/register-nxp), and [Laird](https://app.memfault.com/register-laird) devices.
  * [rollbar.com](https://rollbar.com/) — Exception and error monitoring, free plan with 5,000 errors/month, unlimited users, 30 days retention
  * [Semaphr](https://semaphr.com) — Free all-in-one kill switch for your mobile apps.
  * [sentry.io](https://sentry.io/) — Sentry tracks app exceptions in real-time and has a small free plan. Free for 5k errors per month/ 1 user, unrestricted use if self-hosted
  * [Whitespace](https://whitespace.dev) – One-click bug reports straight in your browser. Free plan with unlimited recordings for personal use.

**[⬆️ Back to Top](#table-of-contents)**

## Search

  * [algolia.com](https://www.algolia.com/) — Hosted search solution with typo-tolerance, relevance, and UI libraries to easily create search experiences. The free "Build" plan includes 1M documents and 10K searches/month. Also offers [developer documentation search](https://docsearch.algolia.com/) for free.
  * [bonsai.io](https://bonsai.io/) — Free 1 GB memory and 1 GB storage
  * [CommandBar](https://www.commandbar.com/) - Unified Search Bar as-a-service, web-based UI widget/plugin that allows your users to search contents, navigations, features, etc. within your product, which helps discoverability. Free for up to 1,000 Monthly Active Users, unlimited commands.
  * [searchly.com](http://www.searchly.com/) — Free 2 indices and 20 MB storage

**[⬆️ Back to Top](#table-of-contents)**

## Education and Career Development

  * [Cisco Networking Academy, Skills for All](https://skillsforall.com/) - Offers free certification-aligned courses in topics like cybersecurity, networking, and Python.
  * [DeepLearning.AI Short Courses](https://www.deeplearning.ai/short-courses/) - Free short courses from industry-leading experts to get hands-on experience with the latest generative AI tools and techniques in an hour or less.
  * [DevNet Academy](https://devnet-academy.com/) – Free, self-paced training for the Cisco DevNet Expert / CCIE Automation certification. Covers Python Click and Flask-RESTx.
  * [Django-tutorial.dev](https://django-tutorial.dev) - Free online guides for learning Django as their first framework & gives free dofollow backlink to articles written by users.
  * [edX](https://www.edx.org/) - Offers access to over 4,000 free online courses from 250 leading institutions, including Harvard and MIT, specializing in computer science, engineering, and data science.
  * [Exercism](https://exercism.org) – Free, open-source programming education in over 75 programming languages, with human mentoring. A nonprofit organisation.
  * [Free Professional Resume Templates & Editor](https://www.overleaf.com/latex/templates/tagged/cv) - Free platform with lots of Resume templates of Experienced Professionals, ready to clone and edit fully and download, ATS optimized.
  * [FreeCodeCamp](https://www.freecodecamp.org/) - Open-source platform offering free courses and certifications in Data Analysis, Information Security, Web Development, and more.
  * [Full Stack Open](https://fullstackopen.com/en/) – Free university-level course on modern web development with React, Node.js, GraphQL, TypeScript, and more. Fully online and self-paced.
  * [Interactive CV](https://interactive-cv.com) — AI-powered resume builder with real-time editing and ATS optimization. Free tier includes automatic CV conversion to premium templates (Harvard, Europass), PDF export, job tracker with unlimited job posting insights and CV sharing with chat/voice features.
  * [Khan Academy](https://www.khanacademy.org/computing/computer-programming) - Free online guides for learning basic and advanced HTML/CSS, JavaScript and SQL.
  * [LabEx](https://labex.io) - Develop skills in Linux, DevOps, Cybersecurity, Programming, Data Science, and more through interactive labs and real-world projects.
  * [MIT OpenCourseWare](https://ocw.mit.edu/) - MIT OpenCourseWare is an online publication of materials from over 2,500 MIT courses, freely sharing knowledge with learners and educators around the world. Youtube channel can be found at [@mitocw](https://www.youtube.com/@mitocw/featured)
  * [Roadmap.sh](https://roadmap.sh) - Free learning roadmaps covering all aspects of development from Blockchain to UX Design.
  * [The Odin Project](https://www.theodinproject.com/) - Free, open-source platform with a curriculum focused on JavaScript and Ruby for web development.
  * [W3Schools](https://www.w3schools.com/) - Offers free tutorials on web development technologies like HTML, CSS, JavaScript, and more.

**[⬆️ Back to Top](#table-of-contents)**

## Email

  * [10minutemail](https://10minutemail.com) - Free, temporary email for testing.
  * [AhaSend](https://ahasend.com) - Transactional email service, free for 1000 emails per month, with unlimited domains, team members, webhooks and message routes in the free plan.
  * [AnonAddy](https://anonaddy.com) - Open-source anonymous email forwarding, create unlimited email aliases for free
  * [Antideo](https://www.antideo.com) — 10 API requests per hour for email verification, IP, and phone number validation in the free tier. No Credit Cards are required.
  * [Brevo](https://www.brevo.com/) — 9,000 emails/month, 300 emails/day free
  * [Bump](https://bump.email/) - Free 10 Bump email addresses, one custom domain
  * [Burnermail](https://burnermail.io/) – Free 5 Burner Email Addresses, 1 Mailbox, 7-day Mailbox History
  * [Buttondown](https://buttondown.email/) — Newsletter service. Up to 100 subscribers free
  * [Contact.do](https://contact.do/) — Contact form in a link (bitly for contact forms)
  * [debugmail.io](https://debugmail.io/) — Easy to use testing mail server for developers
  * [dkimvalidator.com](https://dkimvalidator.com/) - Test if the email's DNS/SPF/DKIM/DMARC settings are correct, free service by roundsphere.com
  * [DNSExit](https://dnsexit.com/) - Up to 2 Email addresses under your domain for free with 100MB of storage space. IMAP, POP3, SMTP, SPF/DKIM support.
  * [EmailJS](https://www.emailjs.com/) – This is not an entire email server; this is just an email client that you can use to send emails right from the client without exposing your credentials, the free tier has 200 monthly requests, 2 email templates, Requests up to 50Kb, Limited contacts history.
  * [EmailLabs.io](https://emaillabs.io/en) — Send up to 9,000 Emails for free every month, up to 300 emails daily.
  * [EmailOctopus](https://emailoctopus.com) - Up to 2,500 subscribers and 10,000 emails per month free
  * [Emailvalidation.io](https://emailvalidation.io) - 100 free email verifications per month
  * [EtherealMail](https://ethereal.email) - Ethereal is a fake SMTP service, mainly aimed at Nodemailer and EmailEngine users (but not limited to). It's an entirely free anti-transactional email service where messages never get delivered.
  * [forwardemail.net](https://forwardemail.net) — Free email forwarding for custom domains. Create and forward an unlimited amount of email addresses with your domain name (**note**: You must pay if you use .casa, .cf, .click, .email, .fit, .ga, .gdn, .gq, .lat, .loan, .london, .men, .ml, .pl, .rest, .ru, .tk, .top, .work TLDs due to spam)
  * [Imitate Email](https://imitate.email) - Sandbox Email Server for testing email functionality across build/qa and ci/cd. Free accounts get 15 emails a day forever.
  * [ImprovMX](https://improvmx.com) – Free email forwarding.
  * [Inboxes App](https://inboxesapp.com) — Create up to 3 temporary emails a day, then delete them when you're done from within a handy Chrome extension. Perfect for testing signup flows.
  * [inboxkitten.com](https://inboxkitten.com/) - Free temporary/disposable email inbox, with up to 3-day email auto-deletes. Open source and can be self-hosted.
  * [mail-tester.com](https://www.mail-tester.com) — Test if the email's DNS/SPF/DKIM/DMARC settings are correct, 20 free/month.
  * [Maileroo](https://maileroo.com) - SMTP relay and email API for developers. 5,000 emails per month, unlimited domains, free email verification, blacklist monitoring, mail tester and more.
  * [mailcatcher.me](https://mailcatcher.me/) — Catches mail and serves it through a web interface.
  * [mailchannels.com](https://www.mailchannels.com) - Email API with REST API and SMTP integrations, free for upto 3,000 emails/month.
  * [Mailcheck.ai](https://www.mailcheck.ai/) - Prevent users to sign up with temporary email addresses, 120 requests/hour (~86,400 per month)
  * [Maildroppa](https://maildroppa.com) - Up to 100 subscribers and unlimited emails as well as automations for free.
  * [MailerLite.com](https://www.mailerlite.com) — 1,000 subscribers/month, 12,000 emails/month free
  * [MailerSend.com](https://www.mailersend.com) — Email API, SMTP, 3,000 emails/month free for transactional emails
  * [mailinator.com](https://www.mailinator.com/) — Free, public email system where you can use any inbox you want
  * [Mailjet](https://www.mailjet.com/) — 6,000 emails/month free (200 emails daily sending limit)
  * [mailsac.com](https://mailsac.com) - Free API for temporary email testing, free public email hosting, outbound capture, email-to-slack/websocket/webhook (1,500 monthly API limit)
  * [Mailtrap.io](https://mailtrap.io/) — Email API, SMTP, 3,500 emails/month free for transactional and marketing emails. Email Sandbox - fake SMTP server for development, free plan with one inbox, 100 messages, no team member, two emails/second, no forward rules.
  * [Mutant Mail](https://www.mutantmail.com/) – Free 10 Email IDs, 1 Domain, 1 Mailbox. Single Mailbox for All Email IDs.
  * [OneSignal](https://onesignal.com/) — 10,000 emails/month,No Credit Cards are required.
  * [Parsio.io](https://parsio.io) — Free email parser (Forward email, extract the data, send it to your server)
  * [Plunk](https://useplunk.com) - 3K emails/month for free
  * [Postmark](https://postmarkapp.com/) - 100 emails/month free, unlimited DMARC weekly digests.
  * [Proton Mail](https://proton.me/mail) -  Free secure email account service provider with built-in end-to-end encryption. Free 1GB storage.
  * [Resend](https://resend.com) - Transactional emails API for developers. 3,000 emails/month, 100 emails/day free, one custom domain.
  * [Sender](https://www.sender.net) Up to 15,000 emails/month, up to 2,500 subscribers
  * [Sendpulse](https://sendpulse.com) — 500 subscribers/month, 15,000 emails/month free
  * [SendStreak](https://www.sendstreak.com/) - Email framework as a service, that adds templates, automations, history, etc to your own SMTP server (E.g. AWS, Maileroo, Gmail). Free up to 100 emails/day, no time limit.
  * [SimpleLogin](https://simplelogin.io/) – Open source, self-hostable email alias/forwarding solution. Free 10 Aliases, unlimited bandwidth, unlimited reply/send. Free for educational staff (student, researcher, etc.).
  * [Substack](https://substack.com) — Unlimited free newsletter service. Start paying when you charge for it.
  * [Sweego](https://www.sweego.io/) - European transactional emails API for developers. 100 emails/day free.
  * [temp-mail.io](https://temp-mail.io) — Free disposable temporary email service with multiple emails at once and forwarding
  * [Temp-Mail.org](https://temp-mail.org/en/) - Temporary / Disposable Mail Gen Utilizing a range variety of domain. Email Address refreshes everytime, the page is reloaded. It is entirely free and does not include any pricing for their services.
  * [TempMailDetector.com](https://tempmaildetector.com/) - Verify up to 200 emails a month for free and see if an email is temporary or not.
  * [trashmail.com](https://www.trashmail.com) - Free disposable email addresses with forwarding and automatic address expiration
  * [Tuta](https://tuta.com/) - Free secure email account service provider with built-in end-to-end encryption, no ads, no tracking. Free 1GB storage, one calendar (Tuta also have an [paid plan](https://tuta.com/pricing).). Tuta is also partially [open source](https://github.com/tutao/tutanota), so you can self-host.
  * [Verifalia](https://verifalia.com/email-verification-api) — Real-time email verification API with mailbox confirmation and disposable email address detector; 25 free email verifications/day.
  * [verimail.io](https://verimail.io/) — Bulk and API email verification service. 100 free verifications/month
  * [Wraps](https://wraps.dev) - email automation workflows, 5k tracked events and unlimited contacts free.

**[⬆️ Back to Top](#table-of-contents)**

## Feature Toggles Management Platforms

  * [Abby](https://www.tryabby.com) - Open-Source feature flags & A/B testing. Configuration as Code & Fully Typed Typescript SDKs. Strong integration with Frameworks such as Next.js & React. Generous free tier and cheap scaling options.
  * [ConfigCat](https://configcat.com) - ConfigCat is a developer-centric feature flag service with unlimited team size, excellent support, and a reasonable price tag. Free plan up to 10 flags, two environments, 1 product, and 5 Million requests per month.
  * [Flagsmith](https://flagsmith.com) - Release features with confidence; manage feature flags across web, mobile, and server-side applications. Use our hosted API, deploy to your own private cloud, or run on-premise.
  * [GrowthBook](https://growthbook.io) - Open source feature flag and A/B testing provider with built-in Bayesian statistical analysis engine. Free for up to 3 users, unlimited feature flags and experiments.
  * [Hypertune](https://www.hypertune.com) - Type-safe feature flags, A/B testing, analytics and app configuration, with Git-style version control and synchronous, in-memory, local flag evaluation. Free for up to 5 team members with unlimited feature flags and A/B tests.
  * [Statsig](https://www.statsig.com) - A robust platform for feature management, A/B testing, analytics, and more. Its generous free plan offers unlimited seats, flags, experiments, and dynamic configurations, supporting up to 1 million events per month.
  * [Toggled.dev](https://www.toggled.dev) - Enterprise-ready, scalable multi-regional feature toggles management platform. Free plan up to 10 flags, two environments, unlimited requests. SDK, analytics dashboard, release calendar, Slack notifications, and all other features are included in the endless free plan.


**[⬆️ Back to Top](#table-of-contents)**

## Font

  * [Befonts](https://befonts.com/) - Provides several unique fonts for personal or commercial use.
  * [Bunny](https://fonts.bunny.net) Privacy oriented Google Fonts
  * [dafont](https://www.dafont.com/) - The fonts presented on this website are their authors' property and are either freeware, shareware, demo versions, or public domain.
  * [Everything Fonts](https://everythingfonts.com/) - Offers multiple tools; @font-face, Units Converter, Font Hinter and Font Submitter.
  * [Font of web](https://fontofweb.com/) - Identify all the fonts used on a website and how they are used.
  * [Font Squirrel](https://www.fontsquirrel.com/) - Freeware fonts licensed for commercial work. Hand-selected these typefaces and presented them in an easy-to-use format.
  * [FontGet](https://www.fontget.com/) - Has a variety of fonts available to download and sorted neatly with tags.
  * [fonts.xz.style](https://fonts.xz.style/) free and open source service for delivering font families to websites using CSS.
  * [Fontsensei](https://fontsensei.com/) Opensourced Google fonts tagged by users. With CJK (Chinese,Japanese,Korean) font tags.
  * [Fontshare](https://www.fontshare.com/) - is a free fonts service. It’s a growing collection of professional-grade fonts, 100% free for personal and commercial use.
  * [Google Fonts](https://fonts.google.com/) - Many free fonts are easy and quick to install on a website via a download or a link to Google's CDN.

**[⬆️ Back to Top](#table-of-contents)**

## Forms

  * [FabForm](https://fabform.io/) - Form backend platform for intelligent developers. The free plan allows 250 form submissions per month. Friendly modern GUI. Integrates with Google Sheets, Airtable, Slack, Email, and others.
  * [Feathery](https://feathery.io) - Powerful, developer-friendly form builder. Build signup & login, user onboarding, payment flows, complex financial applications, and more. The free plan allows up to 250 submissions/month and five active forms.
  * [feedback.fish](https://feedback.fish/) - Free plan allows collecting 25 total feedback submissions. Easy to integrate with React and Vue components provided.
  * [Form.taxi](https://form.taxi/) — Endpoint for HTML forms submissions. With notifications, spam blockers, and GDPR-compliant data processing. Free plan for basic usage.
  * [Formcarry.com](https://formcarry.com) - HTTP POST Form endpoint, Free plan allows 100 monthly submissions.
  * [Formester.com](https://formester.com) - Share and embed unique-looking forms on your website—no limits on the number of forms created or features restricted by the plan. Get up to 100 submissions every month for free.
  * [FormKeep.com](https://www.formkeep.com/) - Unlimited forms with 50 monthly submissions, spam protection, email notification, and a drag-and-drop designer that can export HTML. Additional features include custom field rules, teams, and integrations to Google Sheets, Slack, ActiveCampaign, and Zapier.
  * [formlets.com](https://formlets.com/) — Online forms, unlimited single page forms/month, 100 submissions/month, email notifications.
  * [forms.app](https://forms.app/) — Create online forms with powerful features like conditional logic, automatic score calculator, and AI. Collect up to 100 responses with a free plan, embed your forms on a website, or use them with a link.
  * [formspark.io](https://formspark.io/) -  Form to Email service, free plan allows unlimited forms, 250 submissions per month, support by Customer assistance team.
  * [Formspree.io](https://formspree.io/) — Send email using an HTTP POST request. The free tier limits to 50 submissions per form per month.
  * [Formsubmit.co](https://formsubmit.co/) — Easy form endpoints for your HTML forms. Free Forever. No registration is required.
  * [Formware.io](https://formware.io/) — Create fully-responsive and captivating forms in seconds, without knowing how to code, and collect unlimited responses for free!
  * [HeroTofu.com](https://herotofu.com/) - Forms backend with bot detection and encrypted archive. Forward submissions via UI to email, Slack, or Zapier. Use your own front end. No server code is required. The free plan gives unlimited forms and 100 submissions per month.
  * [HeyForm.net](https://heyform.net/) - Drag and drop online form builder. The free tier lets you create unlimited forms and collect unlimited submissions. Comes with pre-built templates, anti-spam, and 100MB file storage.
  * [Kwes.io](https://kwes.io/) - Feature rich form endpoint. Works great with static sites. The free plan includes up to 1 website with up to 50 monthly submissions.
  * [Pageclip](https://pageclip.co/) - The free plan allows one site, one form, and 1,000 monthly submissions.
  * [SimplePDF.eu](https://simplepdf.eu/embed) - Embed a PDF editor on your website and turn any PDF into a fillable form. The free plan allows unlimited PDFs with three submissions per PDF.
  * [smartforms.dev](https://smartforms.dev/) - Powerful and easy form backend for your website, forever free plan allows 50 submissions per month, 250MB file storage, Zapier integration, CSV/JSON export, custom redirect, custom response page, Telegram & Slack bot, single email notifications.
  * [staticforms.xyz](https://www.staticforms.xyz/) - Integrate HTML forms easily without any server-side code for free. After the user submits the form, an email with the form content will be sent to your registered address.
  * [Survicate](https://survicate.com/) — Pull feedback from all sources and send follow-up surveys with one tool. Automatically analyze feedback and extract insights with AI. Free email, website, in-product or mobile surveys, AI survey creator, and 25 monthly responses.
  * [Tally.so](https://tally.so/) - 99% of all the features are free. The free tier lets you have: unlimited forms, unlimited submissions, email notifications, form logic, collect payments, file upload, custom thank you page, and many more.
  * [Typeform.com](https://www.typeform.com/) — Include beautifully designed forms on websites.  The free plan allows only ten fields per form and 100 monthly responses.
  * [Vidhook](https://vidhook.io/) - Collect feedback using delightful surveys with high response rates. Free plan includes 1 active survey, 25 responses per survey and customizable templates.
  * [WaiverStevie.com](https://waiverstevie.com) - Electronic Signature platform with a REST API. You can receive notifications with webhooks. Free plan watermarks signed documents but allow unlimited envelopes + signatures.
  * [Web3Forms](https://web3forms.com) - Contact forms for Static & JAMStack Websites without writing backend code. The free plan allows Unlimited Forms, Unlimited Domains & 250 Submissions per month.
  * [Wufoo](https://www.wufoo.com/) - Quick forms to use on websites. The free plan has a limit of 100 submissions each month.

**[⬆️ Back to Top](#table-of-contents)**

## Generative AI

  * [Arize AX](https://arize.com) - AI engineering platform that helps AI eng/PMs, evaluate, and observe AI applications and agents with built-in Alyx agent. Free product inlcudes 25k spans and ingestion volume of 1gb per month.
  * [Audio Enhancer](https://voice-clone.org/tools/audio-enhancer) — AI-powered audio enhancer SaaS that removes noise and echo while preserving natural vocal clarity. totally Free: unlimited one-click enhancements, no login required, supports MP3/WAV/FLAC
  * [Braintrust](https://www.braintrustdata.com/) - Evals, prompt playground, and data management for Gen AI. Free plan gives upto 1,000 private eval rows/week.
  * [Clair](https://askclair.ai/) - Clinical AI Reference. Students have free access to the professional tool suite, which includes Open Search, Clinical Summary, Med Review, Drug Interactions, ICD-10 Codes, and Stewardship. Additionally, a free trial for the professional suite is available.
  * [Comet Opik](https://www.comet.com/site/products/opik/) - Evaluate, test, and ship LLM applications across your dev and production lifecycles. [#opensource](https://github.com/comet-ml/opik/)
  * [Keywords AI](https://keywordsai.co) - The best LLM monitoring platform. One format to call 200+ LLMs with 2 lines of code. 10,000 free requests every month and $0 for platform features!
  * [Langfuse](https://langfuse.com/) - Open-source LLM engineering platform that helps teams collaboratively debug, analyze, and iterate on their LLM applications. Free forever plan includes 50k observations per month and all platform features. [#opensource](https://github.com/langfuse/langfuse)
  * [Langtrace](https://langtrace.ai) - enables developers to trace, evaluate, manage prompts and datasets, and debug issues related to an LLM application’s performance. It creates open telemetry standard traces for any LLM which helps with observability and works with any observability client. Free plan offers 50K traces/month.
  * [LangWatch](https://langwatch.ai) - A LLMOps platform helping AI teams measure, monitor, and optimize LLM applications for reliability, cost-efficiency, and performance. With a powerful DSPy component, we enable seamless collaboration between engineers and non-technical teams to fine-tune and productionize GenAI products. Free plan includes all platform features, 1k traces/month and 1 workflow DSPy optimizers. [#opensource](https://github.com/langwatch/langwatch)
  * [Mediaworkbench.ai](https://mediaworkbench.ai) - MediaWorkbench.ai offers 100,000 free words for Azure OpenAI, DeepSeek, and Google Gemini models, enabling users to access powerful tools for code generation, deep research, and image creation.
  * [OpenRouter](https://openrouter.ai/models?q=free) - Provides various free AI models including DeepSeek R1, V3, Llama, and Moonshot AI. These models excel in natural language processing and are suitable for diverse development needs. Note that while these models are free to use, they are subject to rate limits. Additionally, OpenRouter offers paid models for more advanced requirements, for instance Claude, OpenAI, Grok, Gemini, and Nova.
  * [Othor AI](https://othor.ai/) - An AI-native fast, simple, and secure alternative to popular business intelligence solutions like Tableau, Power BI, and Looker. Othor utilizes large language models (LLMs) to deliver custom business intelligence solutions in minutes. The Free Forever plan provides one workspace with five datasource connections for one user, with no limits on analytics. [#opensource](https://github.com/othorai/othor.ai)
  * [Pollinations.AI](https://pollinations.ai/) - easy-to-use, free image generation AI with free API available. No signups or API keys required, and several option for integrating into a website or workflow. [#opensource](https://github.com/pollinations/pollinations)
  * [Portkey](https://portkey.ai/) - Control panel for Gen AI apps featuring an observability suite & an AI gateway. Send & log up to 10,000 requests for free every month.
  * [ReportGPT](https://ReportGPT.app) - AI Powered Writing Assistant. The entire platform is free as long as you bring your own API key.
  * [Zenable](https://zenable.io) - Instantly auto-fix outputs from tools like Cursor, Windsurf, and Copilot to meet your company's quality and compliance standards using guardrails built with Policy as Code. The free tier includes 100 tools calls per day to the MCP server and 25 free automated pull request reviews per day via the GitHub App.

**[⬆️ Back to Top](#table-of-contents)**

## CDN and Protection

  * [bootstrapcdn.com](https://www.bootstrapcdn.com/) — CDN for bootstrap, bootswatch and fontawesome.io
  * [CacheFly](https://portal.cachefly.com/signup/free2023) - Up to 5 TB per month of Free CDN traffic, 19 Core PoPs , 1 Domain and Universal SSL.
  * [cdnjs.com](https://cdnjs.com/) — Simple. Fast. Reliable. Content delivery at its finest. cdnjs is a free and open-source CDN service trusted by over 11% of all websites, powered by Cloudflare.
  * [developers.google.com](https://developers.google.com/speed/libraries/) — The Google Hosted Libraries is a content distribution network for the most popular Open Source JavaScript libraries
  * [Gcore](https://gcorelabs.com/) Global content delivery network, 1 TB and 1 million requests per month free and free DNS hosting
  * [jsdelivr.com](https://www.jsdelivr.com/) — A free, fast, and reliable open-source CDN. Supports npm, GitHub, WordPress, Deno, and more.
  * [Microsoft Ajax](https://docs.microsoft.com/en-us/aspnet/ajax/cdn/overview) — The Microsoft Ajax CDN hosts popular third-party JavaScript libraries such as jQuery and enables you to easily add them to your Web application
  * [Namecheap Supersonic](https://www.namecheap.com/supersonic-cdn/#free-plan) — Free DDoS protection
  * [ovh.ie](https://www.ovh.ie/ssl-gateway/) — Free DDoS protection and SSL certificate
  * [PromoProxy](https://promoproxy.net/) - Free cloud Secure Web Gateway. Free plan includes up to 5 users and 1 GB per day.
  * [raw.githack.com](https://raw.githack.com/) — A modern replacement of **rawgit.com** which simply hosts file using Cloudflare
  * [Skypack](https://www.skypack.dev/) — The 100% Native ES Module JavaScript CDN. Free for 1 million requests per domain per month.
  * [statically.io](https://statically.io/) — CDN for Git repos (GitHub, GitLab, Bitbucket), WordPress-related assets, and images
  * [Stellate](https://stellate.co/) - Stellate is a blazing-fast, reliable CDN for your GraphQL API and free for two services.
  * [toranproxy.com](https://toranproxy.com/) — Proxy for Packagist and GitHub. Never fail CD. Free for personal use, one developer, no support
  * [UNPKG](https://unpkg.com/) — CDN for everything on npm
  * [weserv](https://images.weserv.nl/) — An image cache & resize service. Manipulate images on the fly with a worldwide cache.

**[⬆️ Back to Top](#table-of-contents)**

## PaaS

  * [ampt.dev](https://getampt.com/) - Ampt lets teams build, deploy, and scale JavaScript apps on AWS without complicated configs or managing infrastructure. Free Preview plan includes 500 invocations hourly, 2,500 invocations daily and 50,000 invocations monthly. Custom domains are allowed only in the paid plans.
  * [anvil.works](https://anvil.works) - Web app development with nothing but Python. Free tier with unlimited apps and 30-second timeouts.
  * [Apply.build](https://apply.build/) — Build and deploy your GitHub app for free with 0.5 vCPUs / 512 MiB RAM, European servers, automatic firewall, real-time performance metrics. Run Node.js, Python, Go, Java, static sites, microservices, and more.
  * [appwrite](https://appwrite.io) - Unlimited projects with no project pausing (supports websockets) and authentication service. 1 Database, 3 Buckets, 5 Functions per project in free tier.
  * [Choreo](https://wso2.com/choreo/) - AI-native internal developer platform as a service. The free tier includes up to 5 components and $100 credits per month.
  * [codenameone.com](https://www.codenameone.com/) — Open source, cross-platform, mobile app development toolchain for Java/Kotlin developers. Free for commercial use with an unlimited number of projects
  * [Daestro](https://daestro.com) - Run compute jobs across Cloud Providers & On-Prem. The free tier includes up to 10 concurrent job runs, 2 compute spawns, self-hosted compute, 1 cloud provider, 1 container registry and 1 cron job.
  * [Deno Deploy](https://deno.com/deploy) - Distributed system that runs JavaScript, TypeScript, and WebAssembly at the edge worldwide. The free tier includes 100,000 requests per day and 100 GiB data transfers per month.
  * [domcloud.co](https://domcloud.co) – Linux hosting service that provides CI/CD with GitHub, SSH, and MariaDB/Postgres database. The free version has 1 GB storage and 1 GB network/month limit and is limited to a free domain.
  * [encore.dev](https://encore.dev/) — Backend framework using static analysis to provide automatic infrastructure, boilerplate-free code, and more. Includes free cloud hosting for hobby projects.
  * [flightcontrol.dev](https://flightcontrol.dev/) - Deploy web services, databases, and more on your own AWS account with a Git push style workflow. Free tier for users with 1 developer on personal GitHub repos. AWS costs are billed through AWS, but you can use credits and the AWS free tier.
  * [gigalixir.com](https://gigalixir.com/) - Gigalixir provides one free instance that never sleeps and a free-tier PostgreSQL database limited to 2 connections, 10, 000 rows and no backups for Elixir/Phoenix apps.
  * [Koyeb](https://www.koyeb.com) - Koyeb is a developer-friendly serverless platform to deploy apps globally. Seamlessly run Docker containers, web apps, and APIs with git-based deployment, native autoscaling, a global edge network, and built-in service mesh and discovery. Free Instance lets you deploy a web service in Frankfurt, Germany or Washington, D.C., US. Free Managed Postgres database available in Frankfurt (Germany), Washington, D.C. (US), and Singapore. 512MB memory, 2GB storage, and 0.1 CPU.
  * [leapcell](https://leapcell.io/) - Leapcell is a reliable distributed applications platform, providing everything you need to seamlessly support your rapid growth. The free plan includes 100k service invocations, 10k async tasks and 100k Redis commands.
  * [Northflank](https://northflank.com) — Build and deploy microservices, jobs, and managed databases with a powerful UI, API & CLI. Seamlessly scale containers from version control and external Docker registries. The free tier includes two services, two cron jobs and 1 database.
  * [pipedream.com](https://pipedream.com) - An integration platform built for developers. Develop any workflow based on any trigger. Workflows are code you can run [for free](https://docs.pipedream.com/pricing/). No server or cloud resources to manage.
  * [Railway](https://railway.app/) - Deploy anything with git-based deployments, automatic CI/CD, and built-in databases. Free tier includes $5 of credits each month
  * [pythonanywhere.com](https://www.pythonanywhere.com/) — Cloud Python app hosting. Beginner account is free, 1 Python web application at your-username.pythonanywhere.com domain, 512 MB private file storage, one MySQL database
  * [WunderGraph](https://cloud.wundergraph.com) - An open-source platform that allows you to  quickly build, ship and manage modern APIs. Built-in CI/CD, GitHub integration, and automatic HTTPS. Up to 3 projects, 1GB egress, 300 minutes of build time per month on the [free plan](https://wundergraph.com/pricing)
  * [YepCode](https://yepcode.io) - All-in-one platform to connect APIs and services in a serverless environment. It brings all the agility and benefits of NoCode tools but with all the power of using programming languages. The free tier includes [1.000 yeps](https://yepcode.io/pricing/).
  * [Zeabur](https://zeabur.com) - Deploy your services with one click. Free for three services, with US$ 5 free credits per month.

**[⬆️ Back to Top](#table-of-contents)**

## BaaS

  * [Activepieces](https://www.activepieces.com) - Build automation flows to connect several apps together in your app's backend. For example, send a Slack message or add a Google Sheet row when an event fires in your app. Free up to 5,000 tasks per month.
  * [back4app.com](https://www.back4app.com) - Back4App is an easy-to-use, flexible and scalable backend based on Parse Platform.
  * [backendless.com](https://backendless.com/) — Mobile and Web Baas, with 1 GB file storage free, push notifications of 50,000/month, and 1000 data objects in the table.
  * [bismuth.cloud](https://www.bismuth.cloud/) — Our AI will boostrap your Python API on our function runtime and hosted storage, build and host for free in our online editor or locally with your favorite tools.
  * [Claw.cloud](https://run.claw.cloud) - A PaaS platform offering $5/month in free credits for users with a GitHub account older than 180 days. Perfect for hosting apps, databases, and more. ([Signup Link with free credit](https://ap-southeast-1.run.claw.cloud/signin)).
  * [connectycube.com](https://connectycube.com) - Unlimited chat messages, p2p voice & video calls, files attachments and push notifications. Free for apps up to 1000 users.
  * [convex.dev](https://convex.dev/) - Reactive backend as a service, hosting your data (documents with relationships & serializable ACID transactions), serverless functions, and WebSockets to stream updates to various clients. Free for small projects - up to 1M records, 5M monthly function calls.
  * [ETLR](https://etlr.io) - Define, version, and deploy automation scripts using YAML. A developer-first alternative to drag-and-drop tools. Can be used for scheduled tasks, AI agents, and infrastructure monitoring. Free tier includes 100 credits/month.
  * [Flutter Flow](https://flutterflow.io) — Build your Flutter App UI without writing a single line of code. Also has a Firebase integration. The free plan includes full access to UI Builder and Free templates.
  * [getstream.io](https://getstream.io/) — Build scalable In-App Chat, Messaging, Video and audio, and Feeds in a few hours instead of weeks
  * [IFTTT](https://ifttt.com) — Automate your favorite apps and devices. Free 2 Applets
  * [Integrately](https://integrately.com) — Automate tedious tasks with a single click. Free 100 Tasks, 15 Minute
  * [LeanCloud](https://leancloud.app/) — Mobile backend. 1GB of data storage, 256MB instance, 3K API requests/day, and 10K pushes/day are free. (API is very similar to Parse Platform)
  * [nhost.io](https://nhost.io) - Serverless backend for web and mobile apps. The free plan includes PostgreSQL, GraphQL (Hasura), Authentication, Storage, and Serverless Functions.
  * [onesignal.com](https://onesignal.com/) — Unlimited free push notifications. 10,000 email sends per month, with unlimited contacts and access to Auto Warm Up.
  * [paraio.com](https://paraio.com) — Backend service API with flexible authentication, full-text search and caching. Free for one app, 1GB of app data.
  * [pubnub.com](https://www.pubnub.com/) — Free push notifications for up to 1 million messages/month and 100 active daily devices
  * [pushbots.com](https://pushbots.com/) — Push notification service. Free for up to 1.5 million pushes/month
  * [pusher.com](https://pusher.com/beams) — Free, unlimited push notifications for 2000 monthly active users. A single API for iOS and Android devices.
  * [simperium.com](https://simperium.com/) — Move data everywhere instantly and automatically, multi-platform, unlimited sending and storage of structured data, max. 2,500 users/month
  * [Supabase](https://supabase.com) — The Open Source Firebase Alternative to build backends. Free Plan offers Authentication, Realtime Database & Object Storage.
  * [tyk.io](https://tyk.io/) — API management with authentication, quotas, monitoring and analytics. Free cloud offering
  * [zapier.com](https://zapier.com/) — Connect the apps you use to automate tasks. Five zaps every 15 minutes and 100 tasks/month
Update Time, five active automations, webhooks.


**[⬆️ Back to Top](#table-of-contents)**

## Low-code Platform

  * [appsmith](https://www.appsmith.com/) — Low code project to build admin panels, internal tools, and dashboards. Integrates with 15+ databases and any API.
  * [BudiBase](https://budibase.com/) — Budibase is an open-source low-code platform for creating internal apps in minutes. Supports PostgreSQL, MySQL, MSSQL, MongoDB, Rest API, Docker, K8s
  * [Clappia](https://www.clappia.com) — A low-code platform designed for building business process applications with customizable mobile and web apps. Offers a drag-and-drop interface, features like Offline Support, real-time location tracking and integration with various third-party services
  * [lil'bots](https://www.lilbots.io/) - write and run scripts online utilizing free built-in APIs like OpenAI, Anthropic, Firecrawl and others. Great for building AI agents / internal tooling and sharing with team. Free-tier includes full access to APIs, AI coding assistant and 10,000 execution credits / month.
  * [manubes](https://www.manubes.com) - Powerful no-code cloud platform with a focus on industrial production management. Free for one user with 1 million workflow activities a month ([also available in german](https://www.manubes.de)).
  * [Mendix](https://www.mendix.com/) — Rapid Application Development for Enterprises, unlimited accessible sandbox environments supporting total users, 0.5 GB storage and 1 GB RAM per app. Also, Studio and Studio Pro IDEs are allowed in the free tier.
  * [outsystems.com](https://www.outsystems.com/) — Enterprise web development PaaS for on-premise or cloud, free "personal environment" offering allows for unlimited code and up to 1 GB database
  * [ReTool](https://retool.com/) — Low-code platform for building internal applications. Retool is highly hackable. If you can write it with JavaScript and an API, you can make it in Retool. The free tier allows up to five users per month, unlimited apps and API connections.
  * [ToolJet](https://www.tooljet.com/) — Extensible low-code framework for building business applications. Connect to databases, cloud storages, GraphQL, API endpoints, Airtable, etc., and build apps using drag-and-drop application builder.
  * [UI Bakery](https://uibakery.io) — Low-code platform that enables faster building of custom web applications. Supports building UI using drag and drop with a high level of customization through JavaScript, Python, and SQL. Available as both cloud and self-hosted solutions. Free for up to 5 users.

**[⬆️ Back to Top](#table-of-contents)**

## Web Hosting

  * [Alwaysdata](https://www.alwaysdata.com/) — 1 GB free web hosting with support for MySQL, PostgreSQL, RabbitMQ, .NET, Deno, Elixir, Go, Java, Lua, Node.js, PHP, Python, Ruby, Rust. Custom web servers, access via FTP, WebDAV and SSH. Mailbox, mailing list and app installer included. No custom domain on free plan.
  * [Awardspace.com](https://www.awardspace.com) — Free web hosting + a free short domain, PHP, MySQL, App Installer, Email Sending & No Ads.
  * [Bubble](https://bubble.io/) — Visual programming to build web and mobile apps without code, free with Bubble branding.
  * [dAppling Network](https://www.dappling.network/) - Decentralized web hosting platform for Web3 frontends focusing on increasing uptime and security and providing an additional access point for users.
  * [DigitalOcean](https://www.digitalocean.com/pricing) - Build and deploy three static sites for free on the App Platform Starter tier.
  * [FreeFlarum](https://freeflarum.com/) - Community-powered free Flarum hosting for up to 250 users (donate to remove the watermark from the footer).
  * [Kinsta Static Site Hosting](https://kinsta.com/static-site-hosting/) — Deploy up to 100 static sites for free, custom domains with SSL, 100 GB monthly bandwidth, 260+ Cloudflare CDN locations.
  * [MDB GO](https://mdbgo.com/) - Free hosting for one project with two weeks Container TTL, 500 MB RAM per project, SFTP - 1G disk space.
  * [Neocities](https://neocities.org) — Static, 1 GB free storage with 200 GB Bandwidth.
  * [Netlify](https://www.netlify.com/) — Builds, deploys and hosts static site/app free for 300 credits/month (equals 30 GB bandwidth).
  * [Oaysus](https://oaysus.com) - Visual page builder for developer-built React, Vue, or Svelte components. Free tier includes 1 site with unlimited pages, form submissions, and global CDN hosting.
  * [PandaStack](https://www.pandastack.io/) — An eco-system for developers includes web hosting in different formats (static web hosting, container based web hosting, wordpress and so many other managed apps available in couple of clicks ). One free web hosting (static or containered) and one free database with 100GB Bandwidth and 300 Build mins/month.
  * [pantheon.io](https://pantheon.io/) — Drupal and WordPress hosting, automated DevOps, and scalable infrastructure. Free for developers and agencies. No custom domain.
  * [Qoddi](https://qoddi.com) - PaaS service similar to Heroku with a developer-centric approach and all-inclusive features. Free tier for static assets, staging, and developer apps.
  * [readthedocs.org](https://readthedocs.org/) — Free documentation hosting with versioning, PDF generation, and more
  * [render.com](https://render.com) — Unified cloud to build and run apps and sites with free SSL, a global CDN, private networks, auto-deploys from Git, and completely free plans for web services, databases, and static web pages.
  * [Serv00.com](https://serv00.com/) — 3 GB of free web hosting with daily backups (7 days). Support: Crontab jobs, SSH access, repositories (GIT, SVN, and Mercurial), support: MySQL, PostgreSQL, MongoDB, PHP, Node.js, Python, Ruby, Java, Perl, TCL/TK, Lua, Erlang, Rust, Pascal, C, C++, D, R, and many more.
  * [SourceForge](https://sourceforge.net/) — Find, Create, and Publish Open Source software for free
  * [surge.sh](https://surge.sh/) — Static web publishing for Front-End developers. Unlimited sites with custom domain support
  * [tilda.cc](https://tilda.cc/) — One site, 50 pages, 50 MB storage, only the main pre-defined blocks among 170+ available, no fonts, no favicon, and no custom domain
  * [Vercel](https://vercel.com/) — Build, deploy, and host web apps with free SSL, global CDN, and unique Preview URLs each time you `git push`. Perfect for Next.js and other Static Site Generators.
  * [Versoly](https://versoly.com/) — SaaS-focused website builder - unlimited websites, 70+ blocks, five templates, custom CSS, favicon, SEO and forms. No custom domain.

**[⬆️ Back to Top](#table-of-contents)**

## DNS

  * [1.1.1.1](https://developers.cloudflare.com/1.1.1.1/) - Free public DNS Resolver, which is fast and secure (encrypt your DNS query), provided by Cloudflare. Useful to bypass your internet provider's DNS blocking, prevent DNS query spying, and [to block adult & malware content](https://developers.cloudflare.com/1.1.1.1/1.1.1.1-for-families). It can also be used [via API](https://developers.cloudflare.com/1.1.1.1/encrypted-dns/dns-over-https/make-api-requests). Note: Just a DNS resolver, not a DNS hoster.
  * [1984.is](https://www.1984.is/product/freedns/) — Free DNS service with API and lots of other free DNS features included.
  * [cloudns.net](https://www.cloudns.net/) — Free DNS hosting up to 1 domain with 50 records
  * [deSEC](https://desec.io) - Free DNS hosting with API support, designed with security in mind. Runs on open-source software and is supported by [SSE](https://www.securesystems.de/).
  * [dns.he.net](https://dns.he.net/) — Free DNS hosting service with Dynamic DNS Support
  * [dnspod.com](https://www.dnspod.com/) — Free DNS hosting.
  * [duckdns.org](https://www.duckdns.org/) — Free DDNS with up to 5 domains on the free tier. With configuration guides for various setups.
  * [Dynv6.com](https://dynv6.com/) — Free DDNS service with [API support](https://dynv6.com/docs/apis) and management of a lot of dns record types (like CNAME, MX, SPF, SRV, TXT and others).
  * [freedns.afraid.org](https://freedns.afraid.org/) — Free DNS hosting. Also, provide free subdomains based on numerous public user [contributed domains](https://freedns.afraid.org/domain/registry/). Get free subdomains from the "Subdomains" menu after signing up.
  * [Glauca](https://docs.glauca.digital/hexdns/) – Free DNS hosting for up to 3 domains and DNSSEC support
  * [Hetzner](https://www.hetzner.com/dns-console) – Free DNS hosting from Hetzner with API support.
  * [huaweicloud.com](https://www.huaweicloud.com/intl/en-us/product/dns.html) – Free DNS hosting by Huawei
  * [LocalCert](https://localcert.net) - Free `.localcert.net` subdomains compatible with public CAs for use with-in private networks
  * [luadns.com](https://www.luadns.com/) — Free DNS hosting, three domains, all features with reasonable limits
  * [namecheap.com](https://www.namecheap.com/domains/freedns/) — Free DNS. No limit on the number of domains
  * [nextdns.io](https://nextdns.io) - DNS-based firewall, 300K free queries monthly
  * [noip.at](https://noip.at/) — Free DDNS service without registration, tracking, logging or advertising. No limit to domains.
  * [noip](https://www.noip.com/) — a dynamic DNS service that allows up to 3 hostnames free with confirmation every 30 days
  * [sslip.io](https://sslip.io/) — Free DNS service that when queried with a hostname with an embedded IP address returns that IP address.
  * [VolaryDDNS](https://volaryddns.net) - Free high-performant DDNS with no subscriptions or advertisements
  * [zilore.com](https://zilore.com/en/dns) — Free DNS hosting for 5 domains.
  * [zoneedit.com](https://www.zoneedit.com/free-dns/) — Free DNS hosting with Dynamic DNS Support.
  * [Zonomi](https://zonomi.com/) — Free DNS hosting service with instant DNS propagation. Free plan: 1 DNS zone (domain name) with up to 10 DNS records.

**[⬆️ Back to Top](#table-of-contents)**

## Domain

  * [DigitalPlat](https://domain.digitalplat.org) — Free subdomains.
  * [isroot.in](https://isroot.in) — Free isroot.in subdomains.
  * [pp.ua](https://nic.ua/) — Free pp.ua subdomains.

**[⬆️ Back to Top](#table-of-contents)**

## IaaS

  * [4EVERLAND](https://www.4everland.org/) — Compatible with AWS S3 - APIs, interface operations, CLI, and other upload methods, upload and store files from the IPFS and Arweave networks in a safe, convenient, and efficient manner. Registered users can get 6 GB of IPFS storage and 300MB of Arweave storage for free. Any Arweave file uploads smaller than 150 KB are free.
  * [backblaze.com](https://www.backblaze.com/b2/) — Backblaze B2 cloud storage. Free 10 GB (Amazon S3-like) object storage for unlimited time
  * [C2 Object Storage](https://c2.synology.com/en-us/pricing/object-storage) - S3 compatibility object storage. 15 GB free storage and 15 GB downloads per month.
  * [filebase.com](https://filebase.com/) - S3 Compatible Object Storage Powered by Blockchain. 5 GB free storage for an unlimited duration.

**[⬆️ Back to Top](#table-of-contents)**

## Managed Data Services

  * [8base.com](https://www.8base.com/) - 8base is a full-stack low-code development platform built for JavaScript developers built on top of MySQL and GraphQL and serverless backend-as-a-service. It allows you to start building web applications quickly using a UI app builder and scale quickly, The Free tier includes rows: 2,500, Storage: 500, Serverless computing: 1Gb/h, and client app users: 5.
  * [airtable.com](https://airtable.com/) — Looks like a spreadsheet, but it's a relational database unlimited bases, 1,200 rows/base, and 1,000 API requests/month
  * [Aiven](https://aiven.io/) - Aiven offers free PostgreSQL, MySQL and Valkey (Redis compatible) plans on its open-source data platform. Single node, 1 CPU, 1GB RAM, and for PostgreSQL and MySQL, 1GB storage. Easy migration to more extensive plans or across clouds.
  * [CockroachDB Cloud](https://www.cockroachlabs.com/pricing/) — Free tier offers 50 million RUs and 10 GiB of storage (same as 15$ worth) free per month. ([What's the Request Units](https://www.cockroachlabs.com/docs/cockroachcloud/metrics-request-units.html))
  * [codehooks.io](https://codehooks.io/) — Easy to use JavaScript serverless API/backend and NoSQL database service with functions, Mongdb-ish queries, key/value lookups, a job system, realtime messages, worker queues, a powerful CLI and a web-based data manager. Free plan has 5GB storage and 60/API calls per minute. 2 developers included. No credit-card required.
  * [Couchbase Capella](https://www.couchbase.com/products/capella/) - deploy a forever free tier fully managed database cluster with 1 node and 8GB storage, built for developers to create the next generation of applications across IoT to AI
  * [CrateDB](https://crate.io/) - Distributed Open Source SQL database for real-time analytics. [Free Tier CRFREE](https://crate.io/lp-crfree): One-node with 2 CPUs, 2 GiB of memory, 8 GiB of storage. One cluster per organization, no payment method needed.
  * [filess.io](https://filess.io) - filess.io is a platform where you can create two databases with up to 10 MB per database of the following DBMS for free: MySQL, MariaDB, MongoDB, and PostgreSQL.
  * [InfluxDB](https://www.influxdata.com/) — Timeseries database, free up to 3MB/5 minutes writes, 30MB/5 minutes reads and 10,000 cardinalities series
  * [MemCachier](https://www.memcachier.com/) — Managed Memcache service. Free for up to 25MB, 1 Proxy Server, and basic analytics
  * [MongoDB Atlas](https://www.mongodb.com/cloud/atlas) — free tier gives 512 MB
  * [Neo4j Aura](https://neo4j.com/cloud/aura/) — Managed native Graph DBMS / analytics platform with a Cypher query language and a REST API. Limits on graph size (50k nodes, 175k relationships).
  * [Neon](https://neon.tech/) — Managed PostgreSQL, 0.5 GB of storage (total), 1 Project ,10 branches, Unlimited Databases, always-available primary branch ( Auto suspend after 5 minutes), 20 hours of Active time per month (total) for non-primary branch compute.
  * [Nile](https://www.thenile.dev/) — A Postgres platform for B2B apps. Unlimited databases, Always available with no shutdown, 1GB of storage (total), 50 million query tokens, autoscaling, unlimited vector embeddings
  * [Prisma Postgres](https://prisma.io/postgres) - Super fast hosted Postgres built on unikernels and running on bare metal, 1GB storage, 10 databases, integrated with Prisma ORM.
  * [restdb.io](https://restdb.io/) - a fast and straightforward NoSQL cloud database service. With restdb.io you get schema, relations, automatic REST API (with MongoDB-like queries), and an efficient multi-user admin UI for working with data. The free plan allows 3 users, 2500 records, and 1 API request per second.
  * [scalingo.com](https://scalingo.com/) — Primarily a PaaS but offers a 128MB to 192MB free tier of MySQL, PostgreSQL, or MongoDB
  * [SeaTable](https://seatable.io/) — Flexible, Spreadsheet-like Database built by the Seafile team. unlimited tables, 2,000 lines, 1-month versioning, up to 25 team members.
  * [skyvia.com](https://skyvia.com/) — Cloud Data Platform offers a free tier and all plans are completely free while in beta
  * [StackBy](https://stackby.com/) — One tool that combines spreadsheets' flexibility, databases' power, and built-in integrations with your favorite business apps. The free plan includes unlimited users, ten stacks, and a 2GB attachment per stack.
  * [Tinybird](https://tinybird.co) - A serverless managed ClickHouse with connection-less data ingest over HTTP and lets you publish SQL queries as managed HTTP APIs. There is no time limit on free-tier, 10GB storage + 1000 API requests per day.
  * [Turso by ChiselStrike](https://chiselstrike.com/) - Turso is SQLite Developer Experience in an Edge Database. Turso provides a Free Forever starter plan, 9 GB of total storage, Up to 500 databases, Up to 3 locations, 1 billion row reads per month, and Local development support with SQLite.
  * [Upstash](https://upstash.com/) — Serverless Redis with free tier up to 500K monthly commands, 256MB max database size, and 20 concurrent connections
  * [Xata Lite](https://lite.xata.io/) - Xata Lite is a serverless database with built-in powerful search and analytics. One API, multiple type-safe client libraries, and optimized for your development workflow. The free plan provides 10 branches and 15 GB of storage without pausing or cold starts.

**[⬆️ Back to Top](#table-of-contents)**

## Tunneling, WebRTC, Web Socket Servers and Other Routers

  * [btunnel](https://www.btunnel.in/) — Expose localhost and local tcp server to the internet. Free plan includes file server, custom http request and response headers, basic auth protection and 1 hour tunnel timeout.
  * [cname.dev](https://cname.dev/) — Free and secure dynamic reverse proxy service.
  * [conveyor.cloud](https://conveyor.cloud/) — Visual Studio extension to expose IIS Express to the local network or over a tunnel to a public URL.
  * [Expose](https://expose.dev/) - Expose local sites via secure tunnels. The free plan includes an EU Server, Random subdomains, and Single users.
  * [Hamachi](https://www.vpn.net/) — LogMeIn Hamachi is a hosted VPN service that lets you securely extend LAN-like networks to distributed teams with a free plan that allows unlimited networks with up to 5 people
  * [Hookdeck](https://hookdeck.com/pricing) — Develop, test, and monitor your webhooks from anywhere. 100K requests and 100K attempts per month with three days retention.
  * [localhost.run](https://localhost.run/) — Expose locally running servers over a tunnel to a public URL.
  * [localtunnel](https://theboroer.github.io/localtunnel-www/) — Expose locally running servers over a tunnel to a public URL. Free hosted version, and [open source](https://github.com/localtunnel/localtunnel).
  * [LocalXpose](https://localxpose.io) — Reverse proxy that enables you to expose your localhost servers to the internet. The free plan has 15 minutes tunnel lifetime.
  * [ngrok.com](https://ngrok.com/) — Expose locally running servers over a tunnel to a public URL.
  * [Pinggy](https://pinggy.io) — Public URLs for localhost with a single command, no downloads required. HTTPS / TCP / TLS tunnels. The free plan has 60 minutes tunnel lifetime.
  * [Radmin VPN](https://www.radmin-vpn.com/) — Connect multiple computers together via a VPN-enabling LAN-like network. Unlimited peers. (Hamachi alternative)
  * [serveo](https://serveo.net/) — Expose local servers to the internet. No installation, no signup. Free subdomain, no limits.
  * [stun:global.stun.twilio.com:3478?transport=udp](stun:global.stun.twilio.com:3478?transport=udp) Twilio STUN
  * [stun:stun.l.google.com:19302](stun:stun.l.google.com:19302) - Google STUN
  * [Tailscale](https://tailscale.com/) — Zero config VPN, using the open-source WireGuard protocol. Installs on MacOS, iOS, Windows, Linux, and Android devices. Free plan for personal use with 100 devices and three users.
  * [webhookrelay.com](https://webhookrelay.com) — Manage, debug, fan-out, and proxy all your webhooks to public or internal (i.e. localhost) destinations. Also, expose servers running in a private network over a tunnel by getting a public HTTP endpoint (`https://yoursubdomain.webrelay.io <----> http://localhost:8080`).
  * [Xirsys](https://www.xirsys.com/pricing/) — Unlimited STUN usage + 500 MB monthly TURN bandwidth, capped bandwidth, single geographic region.
  * [ZeroTier](https://www.zerotier.com) — FOSS managed virtual Ethernet as a service. Unlimited end-to-end encrypted networks of 25 clients on the free plan. Clients for desktop/mobile/NA; web interface for configuration of custom routing rules and approval of new client nodes on private networks

**[⬆️ Back to Top](#table-of-contents)**

## Issue Tracking and Project Management

  * [acunote.com](https://www.acunote.com/) — Free project management and SCRUM software for up to 5 team members
  * [asana.com](https://asana.com/) — Free for private project with collaborators
  * [Backlog](https://backlog.com) — Everything your team needs to release great projects in one platform. The free plan offers 1 Project with ten users & 100MB of storage.
  * [Basecamp](https://basecamp.com/personal) - To-do lists, milestone management, forum-like messaging, file sharing, and time tracking. Up to 3 projects, 20 users, and 1GB of storage space.
  * [bitrix24.com](https://www.bitrix24.com/) — Intranet and project management tool. The free plan has 5GB for unlimited users.
  * [cacoo.com](https://cacoo.com/) — Online real-time diagrams: flowchart, UML, network. Free max. 15 users/diagram, 25 sheets
  * [clickup.com](https://clickup.com/) — Project management. Free, premium version with cloud storage. Mobile applications and Git integrations are available.
  * [Clockify](https://clockify.me) - Time tracker and timesheet app that lets you track work hours across projects. Unlimited users, free forever.
  * [Cloudcraft](https://cloudcraft.co/) — Design a professional architecture diagram in minutes with the Cloudcraft visual designer, optimized for AWS with intelligent components that show live data too. Free plan has unlimited private diagrams for single user.
  * [Confluence](https://www.atlassian.com/software/confluence) - Atlassian's content collaboration tool is used to help teams collaborate and share knowledge efficiently. Free plan for up to 10 users.
  * [Crosswork](https://crosswork.app/) - Versatile project management platform. Free for up to 3 projects, unlimited users, 1 GB storage.
  * [diagrams.net](https://app.diagrams.net/) — Online diagrams stored locally in Google Drive, OneDrive, or Dropbox. Free for all features and storage levels
  * [easyretro.io](https://www.easyretro.io/) — Simple and intuitive sprint retrospective tool. The free plan has three public boards and one survey per board per month.
  * [freedcamp.com](https://freedcamp.com/) - tasks, discussions, milestones, time tracking, calendar, files and password manager. Free plan with unlimited projects, users, and file storage.
  * [GForge](https://gforge.com) — Project Management and issue Tracking toolset for complex projects with self-premises and SaaS options. SaaS free plan offers the first five users free & free for Open Source Projects.
  * [gleek.io](https://www.gleek.io) — Free description-to-diagrams tool for developers. Create informal UML class, object, or entity-relationship diagrams using your keyword.
  * [GraphQL Inspector](https://github.com/marketplace/graphql-inspector) - GraphQL Inspector outputs a list of changes between two GraphQL schemas. Every difference is precisely explained and marked as breaking, non-breaking, or dangerous.
  * [Helploom](https://helploom.com) - Customer support software that offers a live chat on the free forever plan. Simple, lightweight and beautiful. Setup is a simple copy-paste script. Built by a developer.
  * [Hygger](https://hygger.io) — Project management platform. The free plan offers unlimited users, projects & boards with 100 MB of Storage.
  * [Ilograph](https://www.ilograph.com/)  — interactive diagrams that allow users to see their infrastructure from multiple perspectives and levels of detail. Charts can be expressed in code. The free tier has unlimited private diagrams with up to 3 viewers.
  * [Jira](https://www.atlassian.com/software/jira) — Advanced software development project management tool used in many corporate environments. Free plan for up to 10 users.
  * [kan.bn](https://kan.bn/) - A powerful, flexible kanban app that helps you organise work, track progress, and deliver results—all in one place. Free plan up to 1 user for unlimited boards, unlimited lists, unlimited cards.
  * [kanbanflow.com](https://kanbanflow.com/) — Board-based project management. Free, premium version with more options
  * [kanbantool.com](https://kanbantool.com/) — Kanban board-based project management. The free plan has two boards and two users, without attachments or files.
  * [Kitemaker.co](https://kitemaker.co) - Collaborate through all phases of the product development process and keep track of work across Slack, Discord, Figma, and Github. Unlimited users, unlimited spaces. Free plan up to 250 work items.
  * [Kiter.app](https://www.kiter.app/) - Let anyone organize their job search and track interviews, opportunities, and connections. Powerful web app and Chrome extension. Completely free.
  * [Kumu.io](https://kumu.io/)  — Relationship maps with animation, decorations, filters, clustering, spreadsheet imports, etc. The free tier allows unlimited public projects. Graph size unlimited. Free private projects for students. Sandbox mode is available if you prefer not to leave your file publicly online (upload, edit, download, discard).
  * [leiga.com](https://www.leiga.com/) — Leiga is a SaaS product that uses AI to automatically manage your projects, helping your team stay focused and unleash immense potential, ensuring your projects progress as planned. Free for up to 10 users, 20 custom fields, 2GB of storage space, Video Recording with AI limited to 5 mins/video, Automation Runs at 20/user/month.
  * [Linear](https://linear.app/) — Issue tracker with a streamlined interface. Free for unlimited members, up to 10MB file upload size, 250 issues (excluding Archive)
  * [Lucidchart](https://www.lucidchart.com/) - An online diagram tool with collaboration features. Free plan with three editable documents, 100 professional templates, and basic collaboration features.
  * [MeisterTask](https://www.meistertask.com/) — Online task management for teams. Free up to 3 projects and unlimited project members.
  * [MeuScrum](https://www.meuscrum.com/en) - Free online scrum tool with kanban board
  * [nTask](https://www.ntaskmanager.com/) — Project management software that enables your teams to collaborate, plan, analyze, and manage everyday tasks. The essential plan is free forever with 100 MB storage and five users/teams. Unlimited workspaces, meetings, assignments, timesheets, and issue tracking.
  * [Plane](https://plane.so/) - Plane is a simple, extensible, open-source project and product management tool. Free for unlimited members, up to 5MB file upload size, 1000 issues.
  * [planitpoker.com](https://www.planitpoker.com/) — Free online planning poker (estimation tool)
  * [point.poker](https://www.point.poker/) - Online Planning Poker (consensus-based estimation tool). Free for unlimited users, teams, sessions, rounds, and votes. You don't need to register.
  * [Pulse.red](https://pulse.red) — Free Minimalistic Time Tracker and Timesheet app for projects.
  * [ScrumFast](https://www.scrumfast.com) - Scrum board with a very intuitive interface, free up to 5 users.
  * [Sflow](https://sflow.io) — sflow.io is a project management tool built for agile software development, marketing, sales, and customer support, especially for outsourcing and cross-organization collaboration projects. Free plan up to 3 projects and five members.
  * [Shake](https://www.shakebugs.com/) - In-app bug reporting and feedback tool for mobile apps. Free plan, ten bug reports per app/month.
  * [Shortcut](https://shortcut.com/) - Project management platform. Free for up to 10 users forever.
  * [taiga.io](https://taiga.io/) — Project management platform for startups and agile developers, free for Open Source
  * [taskade.com](https://www.taskade.com/) — Real-time collaborative task lists and team outlines. The free plan has one workspace with unlimited tasks and projects; 1GB file storage; 1-week project history; and five attendees per video meeting.
  * [Teaminal](https://www.teaminal.com) - Standup, retro, and sprint planning tool for remote teams. Free for up to 15 users.
  * [teamwork.com](https://teamwork.com/) — Project management & Team Chat. Free for five users and two projects. Premium plans are available.
  * [teleretro.com](https://www.teleretro.com/) — Simple and fun retrospective tool with icebreakers, gifs and emojis. The free plan includes three retros and unlimited members.
  * [Tenzu](https://tenzu.net/) — Lightweight project management tool for agile teams. The SaaS relies on free contributions; users can always choose to give 0 and there is no features paywall {[more details](https://tenzu.net/pricing/)}
  * [titanapps.io](https://titanapps.io/) — productivity tools for Jira and monday.com offering structured checklists, templates, and approvals inside issues/tasks. Free plan available for small teams.
  * [todoist.com](https://todoist.com/) — Collaborative and individual task management. The free plan has: 5 active projects, five users in the project, file uploading up to 5MB, three filters, and one week of activity history.
  * [Toggl](https://toggl.com/) — Provides two free productivity tools. [Toggl Track](https://toggl.com/track/) for time management and tracking app with a free plan provides seamless time tracking and reporting designed with freelancers in mind. It has unlimited tracking records, projects, clients, tags, reporting, and more. And [Toggl Plan](https://toggl.com/plan/) for task planning with a free plan for solo developers with unlimited tasks, milestones, and timelines.
  * [trello.com](https://trello.com/) — Board-based project management. Unlimited Personal Boards, 10 Team Boards.
  * [Tweek](https://tweek.so/) — Simple Weekly To-Do Calendar & Task Management.
  * [Wikifactory](https://wikifactory.com/) — Product designing Service with Projects, VCS & Issues. The free plan offers unlimited projects & collaborators and 3GB storage.
  * [Yodiz](https://www.yodiz.com/) — Agile development and issue tracking. Free up to 3 users, unlimited projects.
  * [YouTrack](https://www.jetbrains.com/youtrack/buy/#edition=incloud) — Free hosted YouTrack (InCloud) for FOSS projects and private projects (free for three users). Includes time tracking and agile boards
  * [zenhub.com](https://www.zenhub.com) — The only project management solution inside GitHub. Free for public repos, OSS, and nonprofit organizations
  * [zenkit.com](https://zenkit.com) — Project management and collaboration tool. Free for up to 5 members, 5 GB attachments.
  * [Zube](https://zube.io) — Project management with free plan for 4 Projects & 4 users. GitHub integration is available.

**[⬆️ Back to Top](#table-of-contents)**

## Storage and Media Processing

  * [AndroidFileHost](https://androidfilehost.com/) - Free file-sharing platform with unlimited speed, bandwidth, file count, download count, etc. It is mainly aimed for Android dev-related files like APK build, custom ROM & modifications, etc. But seems to accept any other files as well.
  * [borgbase.com](https://www.borgbase.com/) — Simple and secure offsite backup hosting for Borg Backup. 10 GB free backup space and two repositories.
  * [cloudinary.com](https://cloudinary.com/) — Image upload, powerful manipulations, storage, and delivery for sites and apps, with Ruby, Python, Java, PHP, Objective-C, and more libraries. The free tier includes 25 monthly credits. One credit equals 1,000 image transformations, 1 GB of storage, or 1 GB of CDN usage.
  * [degoo.com](https://degoo.com/) – AI based cloud storage with free up to 20 GB, three devices, 5 GB referral bonus (90 days account inactivity).
  * [Dropshare](https://dropsha.re) - Zero-knowledge file sharing. End-to-end encrypted file sharing with AES-256-GCM encryption, client-side processing, and zero server-side data access. Free uploads for files up to 1GB with no data collection.
  * [embed.ly](https://embed.ly/) — Provides APIs for embedding media in a webpage, responsive image scaling, and extracting elements from a webpage. Free for up to 5,000 URLs/month at 15 requests/second
  * [Ente](https://ente.io/) - Ente is an end-to-end encrypted cloud for photos, videos and 2FA secrets. Can also be self-hosted along with a generous forever free-tier of 10GB. For free tier users, only single replica of data is kept.
  * [file.io](https://www.file.io) - 2 GB storage of files. A file is auto-deleted after one download. REST API to interact with the storage. Rate limit one request/minute.
  * [freetools.site](https://freetools.site/) — Free online tools. Convert or edit documents, images, audio, video, and more.
  * [getpantry.cloud](https://getpantry.cloud/) — A simple JSON data storage API perfect for personal projects, hackathons, and mobile apps!
  * [GoFile.io](https://gofile.io/) - Free file sharing and storage platform can be used via web-based UI & also API. unlimited file size, bandwidth, download count, etc. But it will be deleted when a file becomes inactive (no download for more than ten days).
  * [gumlet.com](https://www.gumlet.com/) — Image and video hosting, processing and streaming via CDN. Provides generous free tier of 250 GB / month for videos and 30 GB  / month for images.
  * [icedrive.net](https://www.icedrive.net/) - Simple cloud storage service. 10 GB free storage
  * [image-charts.com](https://www.image-charts.com/) — Unlimited image chart generation with a watermark
  * [ImageEngine](https://imageengine.io/) – ImageEngine is an easy to use global image CDN. Sub 60 sec setup. AVIF and JPEGXL support, WordPress-, Magento-, React-, Vue- plugins and more. Claim your free developer account [here](https://imageengine.io/developer-program/).
  * [imagekit.io](https://imagekit.io) – Image CDN with automatic optimization, real-time transformation, and storage that you can integrate with existing setup in minutes. The free plan includes up to 20GB of bandwidth per month.
  * [ImgBB](https://imgbb.com/) — ImgBB is an unlimited image hosting servce. Drag and drop your image anywhere on the screen. 32 MB / image limit. Receive Direct image links, BBCode and HTML thumbnails after uploading image. Login to see the upload history.
  * [Imgbot](https://github.com/marketplace/imgbot) — Imgbot is a friendly robot that optimizes your images and saves you time. Optimized images mean smaller file sizes without sacrificing quality. It's free for open source.
  * [imgen](https://www.jitbit.com/imgen/) - Free unlimited social cover image generation API, no watermark
  * [imgix](https://www.imgix.com/) - Image Caching, management and CDN. Free plan includes 1000 origin images, infinite transformations and 100 GB bandwidth
  * [internxt.com](https://internxt.com) – Internxt Drive is a zero-knowledge file storage service based on absolute privacy and uncompromising security. Sign up and get 10 GB for free, forever!
  * [kraken.io](https://kraken.io/) — Image optimization for website performance as a service, free plan up to 1 MB file size
  * [LibreQR](https://libreqr.com) — Free QR code generator focused on privacy and no tracking. Free to use with no data collection.
  * [nitropack.io](https://nitropack.io/) - Accelerate your site's speed on autopilot with complete front-end optimization (caching, images and code optimization, CDN). Free for up to 5,000 pageviews/month
  * [npoint.io](https://www.npoint.io/) — JSON store with collaborative schema editing
  * [otixo.com](https://www.otixo.com/) — Encrypt, share, copy, and move all your cloud storage files from one place. The basic plan provides unlimited file transfer with 250 MB max. file size and allows five encrypted files
  * [packagecloud.io](https://packagecloud.io/) — Hosted Package Repositories for YUM, APT, RubyGem and PyPI.  Limited free plans and open-source plans are available via request
  * [pcloud.com](https://www.pcloud.com/) - Cloud storage service. Up to 10 GB of free storage
  * [Pinata IPFS](https://pinata.cloud) — Pinata is the simplest way to upload and manage files on IPFS. Our friendly user interface and IPFS API make Pinata the easiest IPFS pinning service for platforms, creators, and collectors. 1 GB storage free, along with access to API.
  * [plot.ly](https://plot.ly/) — Graph and share your data. The free tier includes unlimited public files and ten private files
  * [podio.com](https://podio.com/) — You can use Podio with a team of up to five people and try out the features of the Basic Plan, except user management
  * [Proton Drive](https://proton.me/drive) - Ultra-secure cloud storage for files and key documents. Free plan offers 5gb of storage space.
  * [QRME.SH](https://qrme.sh) - Fast, beautiful bulk QR code generator – no login, no watermark, no ads. Up to 100 URLs per bulk export.
  * [QuickChart](https://quickchart.io) — Generate embeddable image charts, graphs, and QR codes
  * [redbooth.com](https://redbooth.com) — P2P file syncing, free for up to 2 users
  * [resmush.it](https://resmush.it) — reSmush.it is a FREE API that provides image optimization. reSmush.it has been implemented on the most common CMS such as WordPress, Drupal, or Magento. reSmush.it is the most used image optimization API with more than seven billion images already treated, and it is still Free of charge.
  * [sirv.com](https://sirv.com/) — Smart Image CDN with on-the-fly image optimization and resizing. The free tier includes 500 MB of storage and 2 GB of bandwidth.
  * [SlingSite](https://slingsite.github.io) - Create all the optimized versions of your images and videos. For Free. In bulk. For each image, you get the following formats: AVIF, WEBP and JPG in the three selected resolutions (desktop, tablet, mobile) For videos, you get: WebM (codec VP9), MP4 (codec HEVC aka H.265) and MP4 (codec AVC aka H.264) plus the cover image with the first frame.
  * [sync.com](https://www.sync.com/) - End-to-End cloud storage service. 5 GB of free storage
  * [tinypng.com](https://tinypng.com/) — API to compress and resize PNG and JPEG images, offers 500 compressions for free each month
  * [transloadit.com](https://transloadit.com/) — Handles file uploads and encoding of video, audio, images, documents. Free for Open source, charities, and students via the GitHub Student Developer Pack. Commercial applications get 2 GB free for test driving
  * [twicpics.com](https://www.twicpics.com) - Responsive images as a service. It provides an image CDN, a media processing API, and a frontend library to automate image optimization. The service is free for up to 3GB of traffic/per month.
  * [uploadcare.com](https://uploadcare.com/hub/developers/) — Uploadcare provides the media pipeline  with the ultimate toolkit based on cutting-edge algorithms. All features are available for developers absolutely for free: File Uploading API and UI, Image CDN and Origin Services, Adaptive Delivery, and Smart Compression. The free tier has 3000 uploads, 3 GB traffic, and 3 GB storage.
  * [VaocherApp QR Code Generator](https://www.vaocherapp.com/qr-code-generator) – Easily create custom QR codes for gift cards, gift vouchers, and promotions. Support custom styling, color, logo...

**[⬆️ Back to Top](#table-of-contents)**

## Design and UI

  * [AllTheFreeStock](https://allthefreestock.com) - a curated list of free stock images, audio and videos.
  * [Ant Design Landing Page](https://landing.ant.design/) - Ant Design Landing Page provides a template built by Ant Motion's motion components. It has a rich homepage template, downloads the template code package, and can be used quickly. You can also use the editor to quickly build your own dedicated page.
  * [Backlight](https://backlight.dev/) — With collaboration between developers and designers at heart, Backlight is a complete coding platform where teams build, document, publish, scale, and maintain Design Systems. The free plan allows up to 3 editors to work on one design system with unlimited viewers.
  * [BoxySVG](https://boxy-svg.com/app) — A free installable Web app for drawing SVGs and exporting in SVG, PNG, jpeg, and other formats.
  * [Branition](https://branition.com/colors) - Hand-curated color pallets best fitted for brands.
  * [Calendar Icons Generator](https://calendariconsgenerator.app/) -- Generate an entire year's worth of unique icons in a single click, absolutely FREE
  * [Canva](https://canva.com) - Free online design tool to create visual content.
  * [Carousel Hero](https://carouselhero.com/) - Free online tool to create social media carousels.
  * [Circum Icons](https://circumicons.com) - Consistent open-source icons such as SVG for React, Vue, and Svelte.
  * [clevebrush.com](https://www.cleverbrush.com/) — Free Graphics Design / Photo Collage App. Also, they offer paid integration of it as a component.
  * [cloudconvert.com](https://cloudconvert.com/) — Convert anything to anything. Two hundred eight supported formats including videos and gifs.
  * [CMYK Pantone](https://www.cmyktopantone.com/) - Easily convert CMYK values to the closest Pantone colors and other color models in seconds for free.
  * [CodedThemes](https://codedthemes.com/) - Offers a well-crafted admin dashboard & and UI kits designed to simplify and speed up modern web development.
  * [CodeMyUI](https://codemyui.com) - Handpicked collection of Web Design & UI Inspiration with Code Snippets.
  * [ColorKit](https://colorkit.co/) - Create color palettes online or get inspiration from top palettes.
  * [colorr.me](https://colorr.me/) - Color & Gradient Generator
  * [coolors](https://coolors.co/) - Color palette generator. Free.
  * [css-gradient.com](https://www.css-gradient.com/) - Free tool to quickly generate custom cross-browser CSS gradients. In RGB and HEX format.
  * [css.glass](https://css.glass/) -- Free web app for creating glassmorphic designs using CSS.
  * [DaisyUI](https://daisyui.com/) -- Free. "Use Tailwind CSS but write fewer class names" offers components like buttons.
  * [easyvectors.com](https://easyvectors.com/) — EasyVectors.com is a free SVG vector art stock. Download the best vector graphics absolutely for free.
  * [Excalidraw](https://excalidraw.com/) -- A free online drawing document web page with free save to local and export support.
  * [figma.com](https://www.figma.com) — Online, collaborative design tool for teams; free tier includes unlimited files and viewers with a max of 2 editors and three projects.
  * [Float UI](https://floatui.com/) - free web development tool for quickly creating modern, responsive websites with sleek design, even for non-designers.
  * [Flows](https://flows.sh/) -- A fully customizable product adoption platform for building onboarding and user engagement experiences. Free for up to 250 monthly tracked users.
  * [Flyon UI](https://flyonui.com/)- The Easiest Components Library For Tailwind CSS.
  * [framer.com](https://www.framer.com/) - Framer helps you iterate and animate interface ideas for your next app, website, or product—starting with powerful layouts. For anyone validating Framer as a professional prototyping tool: unlimited viewers, up to 2 editors, and up to 3 projects.
  * [freeforcommercialuse.net](https://freeforcommercialuse.net/) — FFCU Worry-free model/property release stock photos
  * [Glyphs](https://glyphs.fyi/) -- Free, The Mightiest Icons on the Web, Fully editable & truly open source design system.
  * [Gradientos](https://www.gradientos.app) - Makes choosing a gradient fast and easy.
  * [Grapedrop](https://grapedrop.com/) — Responsive, powerful, SEO-optimized web page builder based on GrapesJS Framework. Free for the first five pages, unlimited custom domains, all features, and simple usage.
  * [haikei.app](https://www.haikei.app/) - Haikei is a web app to generate unique SVG shapes, backgrounds, and patterns – ready to use with your design tools and workflow.
  * [hypercolor.dev](https://hypercolor.dev/) -- A curated collection of Tailwind CSS color gradients also provides a variety of generators to create your own.
  * [HyperUI](https://www.hyperui.dev/) -- Free Open Source Tailwind CSS Components.
  * [Icon Horse](https://icon.horse) – Get the highest resolution favicon for any website from our simple API.
  * [iconify.design](https://icon-sets.iconify.design/) -- A collection of over 100 icon packs with a unified interface. Allows you to search for icons across packs and export individual icons as SVGs or for popular web frameworks.
  * [Iconoir](https://iconoir.com) – An open-source icons library with thousands of icons, supporting React, React Native, Flutter, Vue, Figma, and Framer.
  * [Icons8](https://icons8.com) — Icons, illustrations, photos, music, and design tools. Free Plan offers Limited formats in lower resolution. Link to Icons8 when you use our assets.
  * [Image BG Blurer](https://imagebgblurer.com/) -- Generate a blurred background frame for an image, using that image source as the background blur, for Notion, Trello, Jira, and more tools
  * [landen.co](https://www.landen.co) — Generate, edit, and publish beautiful websites and landing pages for your startup. All without code. The free tier allows you to have one website, fully customizable and published on the web.
  * [lensdump.com](https://lensdump.com/) - Free cloud image hosting.
  * [Logo.dev](https://www.logo.dev) - Company logo API with 44M+ brands that's as easy as calling a URL. First 10,000 API calls are free.
  * [Lorem Picsum](https://picsum.photos/) - A Free tool, easy to use, stylish placeholders. After our URL, add your desired image size (width & height), and you'll get a random image.
  * [LottieFiles](https://lottiefiles.com/) - The world’s largest online platform for the world’s most miniature animation format for designers, developers, and more. Access Lottie animation tools and plugins for Android, iOS, and Web.
  * [Lucide](https://lucide.dev) - Free customizable and consistent SVG icon toolkit.
  * [Lunacy](https://icons8.com/lunacy) -- Free graphic design tool with offline support, built-in assets (icons, photos, illustrations), and real-time collaboration. The free tier includes 10 cloud documents, a 30-day history, low-res assets, and basic design tools.
  * [MagicPattern](https://www.magicpattern.design/tools) — A collection of CSS & SVG background generators & tools for gradients, patterns, and blobs.
  * [marvelapp.com](https://marvelapp.com/) — Design, prototyping, and collaboration, free plan limited to one user and project.
  * [Mastershot](https://mastershot.app) - Completely free browser-based video editor. No watermark, up to 1080p export options.
  * [MDBootstrap](https://mdbootstrap.com/) - Free for personal & commercial use Bootstrap, Angular, React, and Vue UI Kits with over 700 components, stunning templates, 1-min installation, extensive tutorials & colossal community.
  * [Mindmup.com](https://www.mindmup.com/) — Unlimited mind maps for free and store them in the cloud. Your mind maps are available everywhere, instantly, from any device.
  * [Mockplus iDoc](https://www.mockplus.com/idoc) - Mockplus iDoc is a powerful design collaboration & handoff tool. Free Plan includes three users and five projects with all features available.
  * [mockupmark.com](https://mockupmark.com/create/free) — Create realistic t-shirt and clothing mockups for social media and E-commerce, 40 free mockups.
  * [Modeldraw.com](https://modeldraw.com) — Complete diagramming platform with UML, system architecture, flowcharts, mind maps, and Agile workflows. Real-time collaboration with unlimited team members, no credit card required.
  * [Mossaik](https://mossaik.app) - Free SVG image generator with different tools like waves, blogs and patterns.
  * [movingpencils.com](https://movingpencils.com) — Fast, browser-based vector editor. Completely free.
  * [Nappy](https://nappy.co/) -- Beautiful photos of Black and Brown people, for free. For commercial and personal use.
  * [NextUI](https://nextui.org/) -- Free. Beautiful, fast, and modern React & Next.js UI library.
  * [NSPolygon](https://nspolygon.com) — Free Stock Photos, Icons & Illustrations.
  * [Octopus.do](https://octopus.do) — Visual sitemap builder. Build your website structure in real time and rapidly share it to collaborate with your team or clients.
  * [OKLCH](https://oklch.net/) -- Free OKLCH color picker and converter for web designers and developers.
  * [okso.app](https://okso.app) - Minimalistic online drawing app. Allows to create fast sketches and visual notes. Exports sketches to PNG, JPG, SVG, and WEBP. Also installable as PWA. Free to use for everyone (no registration is needed).
  * [Pencil](https://github.com/evolus/pencil) - Open source design tool using Electron.
  * [Penpot](https://penpot.app) - Web-based, open-source design and prototyping tool. Supports SVG. Completely free.
  * [pexels.com](https://www.pexels.com/) - Free stock photos for commercial use. Has a free API that allows you to search photos by keywords.
  * [photopea.com](https://www.photopea.com) — A Free, Advanced online design editor with Adobe Photoshop UI supporting PSD, XCF & Sketch formats (Adobe Photoshop, Gimp and Sketch App).
  * [Pixelixe](https://pixelixe.com/) — Create and edit engaging, unique graphics and images online.
  * [pixlr.com](https://pixlr.com/) — Free online browser editor on the level of commercial ones.
  * [Plasmic](https://www.plasmic.app/) - A fast, easy-to-use, robust web design tool and page builder that integrates into your codebase. Build responsive pages or complex components; optionally extend with code; and publish to production sites and apps.
  * [PNG to WebP Converter](https://pngtowebpconverter.com/) - Convert PNG images to WebP images directly in your browser. No upload required, fully client-side processing for maximum privacy and security.
  * [Pravatar](https://pravatar.cc/) - Generate a random/placeholder fake avatar whose URL can be directly hot-linked in your web/app.
  * [Proto.io](https://www.proto.io) - Create fully interactive UI prototypes without coding. The free tier is available when the free trial ends. The free tier includes one user, one project, five prototypes, 100MB of online storage, and a preview of the proto.io app.
  * [Quant Ux](https://quant-ux.com/) - Quant Ux is a prototyping and design tool. - It's completely free and also open source.
  * [resizeappicon.com](https://resizeappicon.com/) — A simple service to resize and manage your app icons.
  * [Responsively App](https://responsively.app) - A free dev tool for faster and more precise responsive web application development.
  * [Rive](https://rive.app) — Create and ship beautiful animations to any platform. Free forever for Individuals. The service is an editor that also hosts all the graphics on their servers. They also provide runtimes for many platforms to run representations made using Rive.
  * [SceneLab](https://scenelab.io) - Online mockup graphics editor with an ever-expanding collection of free design templates
  * [Scrollbar.app](https://scrollbar.app) -- Simple free web app for designing custom scrollbars for the web.
  * [Shadcn Studio](https://shadcnstudio.com/theme-editor) — Preview your theme changes across different components and layouts.
  * [ShadcnUI](https://ui.shadcn.com/) -- Beautifully designed components that you can copy and paste into your apps. Accessible. Customizable. Open Source.
  * [smartmockups.com](https://smartmockups.com/) — Create product mockups, 200 free mockups.
  * [storyset.com](https://storyset.com/) — Create incredible free customized illustrations for your project using this tool.
  * [Superdesigner](https://superdesigner.co) - A collection of free design tools to create unique backgrounds, patterns, shapes, images, and more with just a few clicks.
  * [SVG Converter](https://svgconverter.online/) -- Free JPG/PNG to SVG converter with color palette customization
  * [SVGmix.com](https://www.svgmix.com/) - Massive repository of 300K+ of free SVG icons, collections, and brand logos. It has a simple vector editing program right in the browser for quick file editing.
  * [svgrepo.com](https://www.svgrepo.com/) - Explore, search, and find the best-fitting icons or vectors for your projects using various vector libraries. Download free SVG Vectors for commercial use.
  * [tabler-icons.io](https://tabler-icons.io/) — Over 1500 free copy-and-paste SVG editable icons.
  * [Tailark](https://tailark.com/) - A collection of modern, responsive, pre-built UI blocks designed for marketing websites.
  * [Tailcolors](https://tailcolors.com/) -- A beautiful Tailwind CSS v4 color palette. Instantly preview & copy the perfect Tailwind CSS color class.
  * [Tailkits](https://tailkits.com/) -- A curated collection of Tailwind templates, components, and tools, plus useful generators for code, grids, box shadows, and more.
  * [TeleportHQ](https://teleporthq.io/) - Low-code Front-end Design & Development Platform. TeleportHQ is the collaborative front-end platform to instantly create and publish headless static websites. Three free projects, unlimited collaborators, and free code export.
  * [TW Elements](https://tw-elements.com/) - Free Bootstrap components recreated with Tailwind CSS, but with better design and more functionalities.
  * [tweakcn](https://tweakcn.com/) — Beautiful themes for shadcn/ui. Customize colors, typography, and more in real-time.
  * [UI Avatars](https://ui-avatars.com/) - Generate avatars with initials from names. The URLs can be directly hot-linked in your web/app. Support config parameters via the URL.
  * [unDraw](https://undraw.co/) - A constantly updated collection of beautiful SVG images that you can use completely free without attribution.
  * [Unicorn Platform](https://unicornplatform.com/) - Effortless landing page builder with hosting. One website for free.
  * [unsplash.com](https://unsplash.com/) - Free stock photos for commercial and noncommercial purposes (do-whatever-you-want license).
  * [Updrafts.app](https://updrafts.app) - WYSIWYG website builder for tailwindcss-based designs. Free for non-commercial usage.
  * [vector.express](https://vector.express) — Convert your AI, CDR, DWG, DXF, EPS, HPGL, PDF, PLT, PS and SVG vector fast and easily.
  * [vectr.com](https://vectr.com/) — Free Design App for Web + Desktop.
  * [Vertopal](https://www.vertopal.com) - Vertopal is a free online platform for converting files to various formats. Including developer converters like JPG to SVG, GIF to APNG, PNG to WEBP, JSON to XML, etc.
  * [Volume](https://volumecolor.io) — OKLCH color picker and color palette generator.
  * [walkme.com](https://www.walkme.com/) — Enterprise Class Guidance and Engagement Platform, free plan three walk-thru up to 5 steps/walk.
  * [Wdrfree SVG](https://wdrfree.com/free-svg) - Black and White Free SVG Cut files.
  * [Webflow](https://webflow.com) - WYSIWYG website builder with animations and website hosting. Free for two projects.
  * [Webstudio](https://webstudio.is/) -- Open-source alternative to Webflow. The free plan offers unlimited websites on their domain. Five websites with custom domains. Ten thousand page views/month. 2 GB asset storage.
  * [whimsical.com](https://whimsical.com/) - Collaborative flowcharts, wireframes, sticky notes and mind maps. Create up to 4 free boards.
  * [xLayers](https://xlayers.dev) - Preview and convert Sketch design files into Angular, React, Vue, LitElement, Stencil, Xamarin, and more (free and open source at https://github.com/xlayers/xlayers)
  * [Zeplin](https://zeplin.io/) — Designer and developer collaboration platform. Show designs, assets, and style guides. Free for one project.

**[⬆️ Back to Top](#table-of-contents)**

## Design Inspiration

  * [awwwards.](https://www.awwwards.com/) - [Top websites] A showcase of all the best-designed websites (voted on by designers).
  * [Behance](https://www.behance.net/) - [Design showcase] A place where designers showcase their work. Filterable with categories for UI/UX projects.
  * [dribbble](https://dribbble.com/) - [Design showcase] Unique design inspiration, generally not from real applications.
  * [Landings](https://landings.dev/) - [Web screenshots] Find the best landing pages for your design inspiration based on your preference.
  * [Lapa Ninja](https://www.lapa.ninja/) - [Landing page / UI KIts / Web screenshots] Lapa Ninja is a gallery featuring the best 6025 landing page examples, free books for designers and free UI kits from around the web.
  * [LovelyLanding.net](https://www.lovelylanding.net/) - [Landing Page Designs] Frequently updated landing page screenshots. Includes Desktop, Tablet, and Mobile screenshots.
  * [Mobbin](https://mobbin.design/) - [Mobile screenshots] Save hours of UI & UX research with our library of 50,000+ fully searchable mobile app screenshots.
  * [Mobile Patterns](https://www.mobile-patterns.com/) - [Mobile screenshots] A design inspirational library featuring the finest UI UX Patterns (iOS and Android) for designers, developers, and product makers to reference.
  * [Page Flows](https://pageflows.com/) - [Mobile / web videos and screenshots] Videos of full flows across many mobile and web apps. Also includes screenshots. Highly searchable and indexed.
  * [Refero](https://refero.design/) - [Web screenshots] Tagged and searchable collection of design references from great web applications.
  * [Screenlane](https://screenlane.com/) - [Mobile screenshots] Get inspired and keep up with the latest web & mobile app UI design trends. Filterable by pattern and app.
  * [scrnshts](https://scrnshts.club/) - [Mobile screenshots] A hand-picked collection of the finest app store design screenshots.
  * [Uiland Design](https://uiland.design/) - [Mobile screenshots] Explore Mobile and Web UI Designs from Leading Companies in Africa and the world.

**[⬆️ Back to Top](#table-of-contents)**

## Data Visualization on Maps

  * [Clockwork Micro](https://clockworkmicro.com/) — Map tools that work like clockwork. Fifty thousand free monthly queries (map tiles, db2vector, elevation).
  * [Foursquare](https://developer.foursquare.com/) - Location discovery, venue search, and context-aware content from Places API and Pilgrim SDK.
  * [geoapify.com](https://www.geoapify.com/) - Vector and raster map tiles, geocoding, places, routing, isolines APIs. Three thousand free requests/day.
  * [geocod.io](https://www.geocod.io/) — Geocoding via API or CSV Upload. Two thousand five hundred free queries/day.
  * [geocodify.com](https://geocodify.com/) — Geocoding and Geoparsing via API or CSV Upload. 10k free queries/month.
  * [geojs.io](https://www.geojs.io/) - Highly available REST/JSON/JSONP IP Geolocation lookup API.
  * [Geokeo api](https://geokeo.com) - Geocoding API with language correction and more. Worldwide coverage. 2,500 free daily queries
  * [graphhopper.com](https://www.graphhopper.com/) A free developer package is offered for Routing, Route Optimization, Distance Matrix, Geocoding, and Map Matching.
  * [here](https://developer.here.com/) — APIs and SDKs for maps and location-aware apps. 250k transactions/month for free.
  * [IP Geolocation](https://ipgeolocation.io/) — Free DEVELOPER plan available with 30K requests/month.
  * [ipstack](https://ipstack.com/) - Locate and identify Website Visitors by IP Address
  * [locationiq.com](https://locationiq.com/) — Geocoding, Maps, and Routing APIs. Five thousand requests/day for free.
  * [mapbox.com](https://www.mapbox.com/) — Maps, geospatial services and SDKs for displaying map data.
  * [maps.stamen.com](http://maps.stamen.com/) - Free map tiles and tile hosting.
  * [maptiler.com](https://www.maptiler.com/cloud/) — Vector maps, map services and SDKs for map visualization. Free vector tiles with weekly updates and four map styles.
  * [nominatim.org](https://nominatim.org/) — OpenStreetMap's free geocoding service, providing global address search functionality and reverse geocoding capabilities.
  * [opencagedata.com](https://opencagedata.com) — Geocoding API aggregating OpenStreetMap and other open geo sources. Two thousand five hundred free queries/day.
  * [osmnames](https://osmnames.org/) — Geocoding, search results ranked by the popularity of related Wikipedia page.
  * [positionstack](https://positionstack.com/) - Free geocoding for global places and coordinates. 25,000 Requests per month for personal use.
  * [stadiamaps.com](https://stadiamaps.com/) — Map tiles, routing, navigation, and other geospatial APIs. Two thousand five hundred free map views and API requests/day for non-commercial usage and testing.

**[⬆️ Back to Top](#table-of-contents)**

## Package Build System

  * [build.opensuse.org](https://build.opensuse.org/) — Package build service for multiple distros (SUSE, EL, Fedora, Debian, etc.).
  * [copr.fedorainfracloud.org](https://copr.fedorainfracloud.org) — Mock-based RPM build service for Fedora and EL.
  * [help.launchpad.net](https://help.launchpad.net/Packaging) — Ubuntu and Debian build service.

**[⬆️ Back to Top](#table-of-contents)**

## IDE and Code Editing

  * [Android Studio](https://developer.android.com/studio) — Android Studio provides the fastest tools for building apps on every type of Android device. Open Source IDE is free for everyone and the best Android app development. Available for Windows, Mac, Linux, and even ChromeOS!
  * [AndroidIDE](https://m.androidide.com/) — An Open Source IDE to develop real, Gradle-based Android applications on Android devices.
  * [Apache Netbeans](https://netbeans.apache.org/) — Development Environment, Tooling Platform and Application Framework.
  * [apiary.io](https://apiary.io/) — Collaborative design API with instant API mock and generated documentation (Free for unlimited API blueprints and unlimited users with one admin account and hosted documentation).
  * [BBEdit](https://www.barebones.com/) - BBEdit is a popular and extensible editor for macOS. Free Mode provides a [powerful core feature set](https://www.barebones.com/products/bbedit/comparison.html) and an upgrade path to advanced features.
  * [Binder](https://mybinder.org/) - Turn a Git repo into a collection of interactive notebooks. It is a free public service.
  * [BlueJ](https://bluej.org) — A free Java Development Environment designed for beginners, used by millions worldwide. Powered by Oracle & simple GUI to help beginners.
  * [Bootify.io](https://bootify.io/) - Spring Boot app generator with custom database and REST API.
  * [Brackets](http://brackets.io/) - Brackets is an open-source text editor specifically designed for web development. It is lightweight, easy to use, and highly customizable.
  * [cacher.io](https://www.cacher.io) — Code snippet organizer with labels and support for 100+ programming languages.
  * [cocalc.com](https://cocalc.com/) — (formerly SageMathCloud at cloud.sagemath.com) — Collaborative calculation in the cloud. Browser access to full Ubuntu with built-in collaboration and lots of free software for mathematics, science, data science, preinstalled: Python, LaTeX, Jupyter Notebooks, SageMath, scikitlearn, etc.
  * [code.cs50.io](https://code.cs50.io/) - Visual Studio Code for CS50 is a web app at code.cs50.io that adapts GitHub Codespaces for students and teachers.
  * [Code::Blocks](https://codeblocks.org) — Free Fortran & C/C++ IDE. Open Source and runs on Windows,macOS & Linux.
  * [codepen.io](https://codepen.io/) — CodePen is a playground for the front-end side of the web.
  * [codesandbox.io](https://codesandbox.io/) — Online Playground for React, Vue, Angular, Preact, and more.
  * [codiga.io](https://codiga.io/) — Coding Assistant that lets you search, define, and reuse code snippets directly in your IDE. Free for individual and small organizations.
  * [Components.studio](https://webcomponents.dev/) - Code components in isolation, visualize them in stories, test them, and publish them on npm.
  * [Eclipse Che](https://www.eclipse.org/che/) - Web-based and Kubernetes-Native IDE for Developer Teams with multi-language support. Open Source and community-driven. An online instance hosted by Red Hat is available at [workspaces.openshift.com](https://workspaces.openshift.com/).
  * [ForgeCode](https://forgecode.dev/) — AI-enabled pair programmer for Claude, GPT4 Series, Grok, Deepseek, Gemini and all frontier models. Works natively with your CLI and integrates seamlessly with any IDE. Free tier includes basic AI model access with local processing.
  * [GetVM](https://getvm.io) — Instant free Linux and IDEs chrome sidebar. The free tier includes 5 VMs per day.
  * [JDoodle](https://www.jdoodle.com) — Online compiler and editor for more than 60 programming languages with a free plan for REST API code compiling up to 200 credits per day.
  * [jetbrains.com](https://jetbrains.com/products.html) — Productivity tools, IDEs and deploy tools (aka [IntelliJ IDEA](https://www.jetbrains.com/idea/), [PyCharm](https://www.jetbrains.com/pycharm/), etc). Free license for students, teachers, Open Source and user groups.
  * [JSONPlaceholder](https://jsonplaceholder.typicode.com/) Some REST API endpoints that return some fake data in JSON format. The source code is also available if you would like to run the server locally.
  * [Lazarus](https://www.lazarus-ide.org/) — Lazarus is a Delphi-compatible cross-platform IDE for Rapid Application Development.
  * [MarsCode](https://www.marscode.com/) - A free AI-powered cloud-based IDE.
  * [micro-jaymock](https://micro-jaymock.now.sh/) - Tiny API mocking microservice for generating fake JSON data.
  * [mockable.io](https://www.mockable.io/) — Mockable is a simple configurable service to mock out RESTful API or SOAP web services. This online service allows you to quickly define REST API or SOAP endpoints and have them return JSON or XML data.
  * [mockaroo](https://mockaroo.com/) — Mockaroo lets you generate realistic test data in CSV, JSON, SQL, and Excel formats. You can also create mocks for back-end API.
  * [Mocklets](https://mocklets.com) - an HTTP-based mock API simulator that helps simulate APIs for faster parallel development and more comprehensive testing, with a lifetime free tier.
  * [OneCompiler](https://onecompiler.com/) - Free online compiler supporting 70+ languages including Java, Python, C++, JavaScript.
  * [Paiza](https://paiza.cloud/en/) — Develop Web apps in Browser without needing to set up anything. Free Plan offers one server with 24 24-hour lifetime and 4 hours of running time per day with 2 CPU cores, 2 GB RAM, and 1 GB storage.
  * [PHPSandbox](https://phpsandbox.io/) — Online development environment for PHP
  * [Replit](https://replit.com/) — A cloud coding environment for various program languages.
  * [SoloLearn](https://code.sololearn.com) — A cloud programming playground well-suited for running code snippets. Supports various programming languages. No registration is required for running code, but it is necessary when saving code on their platform. Also offers free courses for beginners and intermediate-level coders.
  * [stackblitz.com](https://stackblitz.com/) — Online/Cloud Code IDE to create, edit, & deploy full-stack apps. Support any popular NodeJs-based frontend & backend frameworks. Shortlink to create a new project: [https://node.new](https://node.new).
  * [Sublime Text](https://www.sublimetext.com/) - Sublime Text is a popular, versatile, and highly customizable text editor used for coding and text editing tasks.
  * [Visual Studio Code](https://code.visualstudio.com/) - Code editor redefined and optimized for building and debugging modern web and cloud applications. Developed by Microsoft.
  * [Visual Studio Community](https://visualstudio.microsoft.com/vs/community/) — Fully-featured IDE with thousands of extensions, cross-platform app development (Microsoft extensions available for download for iOS and Android), desktop, web and cloud development, multi-language support (C#, C++, JavaScript, Python, PHP and more).
  * [VSCodium](https://vscodium.com/) - Community-driven, without telemetry/tracking, and freely-licensed binary distribution of Microsoft’s editor VSCode
  * [wakatime.com](https://wakatime.com/) — Quantified self-metrics about your coding activity using text editor plugins, limited plan for free.
  * [Wave Terminal](https://waveterm.dev/) - Wave is an open-source, cross-platform terminal for seamless workflows. Render anything inline. Save sessions and history. Powered by open web standards. MacOS and Linux.
  * [WebComponents.dev](https://webcomponents.dev/) — In-browser IDE to code web components in isolation with 58 templates available, supporting stories, and tests.
  * [Zed](https://zed.dev/) - Zed is a high-performance, multiplayer code editor from the creators of Atom and Tree-sitter.

**[⬆️ Back to Top](#table-of-contents)**

## Analytics, Events and Statistics

  * [amplitude.com](https://amplitude.com/) — 1 million monthly events, up to 2 apps
  * [AppFit](https://appfit.io) - AppFit is a comprehensive analytics and product management tool designed to facilitate seamless, cross-platform management of analytics and product updates. Free plan includes 10,000 events per month, product journal and weekly insights.
  * [Aptabase](https://aptabase.com) — Open Source, Privacy-Friendly, and Simple Analytics for Mobile and Desktop Apps. SDKs for Swift, Kotlin, React Native, Flutter, Electron, and many others. Free for up to 20,000 events per month.
  * [Avo](https://avo.app/) — Simplified analytics release workflow. Single-source-of-truth tracking plan, type-safe analytics tracking library, in-app debuggers, and data observability to catch all data issues before you release. Free for two workspace members and 1 hour data observability lookback.
  * [Beampipe.io](https://beampipe.io) - Beampipe is simple, privacy-focussed web analytics. free for up to 5 domains & 10k monthly page views.
  * [Census](https://www.getcensus.com/) — Reverse ETL & Operational Analytics Platform. Sync 10 fields from your data warehouse to 60+ SaaS like Salesforce, Zendesk, or Amplitude.
  * [Clicky](https://clicky.com) — Website Analytics Platform. Free Plan for one website with 3000 views analytics.
  * [counter.dev](https://counter.dev) — Web analytics made simple and therefore privacy friendly. Free or pay what you want by donation.
  * [DocBeacon](https://docbeacon.io) - Secure document sharing with document tracking and engagement Analytics. Free plan supports up to 20 PDF documents (10 MB max), 10 contacts, and 2 shares per document with basic analytics for views downloads, time and engagement.
  * [Dwh.dev](https://dwh.dev) - Data Cloud Observability Solution (Snowflake). Free for personal use.
  * [Expensify](https://www.expensify.com/) — Expense reporting, free personal reporting approval workflow
  * [getinsights.io](https://getinsights.io) - Privacy-focused, cookie-free analytics, free for up to 3k events/month.
  * [GoatCounter](https://www.goatcounter.com/) — GoatCounter is an open-source web analytics platform available as a hosted service (free for non-commercial use) or self-hosted app. It aims to offer easy-to-use and meaningful privacy-friendly web analytics as an alternative to Google Analytics or Matomo. The free tier is for non-commercial use and includes unlimited sites, six months of data retention, and 100k pageviews/month.
  * [Google Analytics](https://analytics.google.com/) — Google Analytics
  * [heap.io](https://heap.io) — Automatically captures every user action in iOS or web apps. Free for up to 10K monthly sessions.
  * [Hightouch](https://hightouch.com/) - Hightouch is a Reverse ETL platform that helps you sync customer data from your data warehouse to your CRM, marketing, and support tools. The free tier offers you one destination to sync data to.
  * [Hotjar](https://hotjar.com) — Website Analytics and Reports . Free Plan allows 2000 pageviews/day. One hundred snapshots/day (max capacity: 300). Three snapshot heatmaps can be stored for 365 days. Unlimited Team Members. Also in App and standalone surveys, feedback widgets with screenshots. Free tier allows creating 3 surveys & 3 feedback widgets and collecting 20 responses per month.
  * [LogSpot](https://logspot.io) - Full unified web and product analytics platform, including embeddable analytics widgets and automated robots (slack, telegram, and webhooks). Free plan includes 10,000 events per month.
  * [MetricsWave](https://metricswave.com) — Privacy-friendly Google Analytics alternative for developers. Free plan allows 1M pageviews per month without credit card required.
  * [Mixpanel](https://mixpanel.com/) — 100,000 monthly tracked users, unlimited data history and seats, US or EU data residency
  * [Moesif](https://www.moesif.com) — API analytics for REST and GraphQL. (Free up to 500,000 API calls/mo)
  * [PostHog](https://posthog.com) - Full Product Analytics suite free for up to 1m tracked events per month. Also provides unlimited in-App Surveys with 250/month responses.
  * [Repohistory](https://repohistory.com) - Beautiful dashboard for tracking GitHub repo traffic history longer than 14 days. Free Plan allows users to monitor traffic for a single repository.
  * [Row Zero](https://rowzero.io) - Blazingly fast, connected spreadsheet. Connect directly to data databases, S3, and APIs. Import, analyze, graph, and share millions of rows instantly. Three free (forever) workbooks.
  * [Rybbit](https://rybbit.io) - Open-source and cookieless alternative to Google Analytics that is 10x more intuitive. Free plans has 3,000 monthly events.
  * [Seline](https://seline.so) - Seline is a simple & private website and product analytics. Cookieless, lightweight, independent. Free plan includes 3,000 events per month and provides access to all our features, such as the dashboard, user journeys, funnels, and more.
  * [StatCounter](https://statcounter.com/) — Website Viewer Analytics. Free plan for analytics of 500 most recent visitors.
  * [Statsig](https://statsig.com) - All-in-one platform spanning across analytics, feature flagging, and A/B testing. Free for up to 1m metered events per month.
  * [TraceLog](https://tracelog.io/) - AI Analytics for E-commerce. Ask questions in natural language about your analytics, get actionable recommendations and grow your revenue with AI-powered insights. Free for up to 10k events per month.
  * [Trackingplan](https://www.trackingplan.com/) - Automatically detect digital analytics, marketing data and pixels issues, maintain up-to-date tracking plans, and foster seamless collaboration. Deploy it to your production environment with real traffic or add analytics coverage to your regression tests without writing code.
  * [TrackWith Dicloud](https://dicloud.net/trackwith-privacy-focused-analytics/) - Free lightweight privacy-focused alternative to Google Analytics. Unlimited pageviews, unlimited visitor, unlimited page heatmaps & goal tracking. Free for up to 3 domains and 600 session replay per domain.
  * [Umami](https://umami.is/) - Simple, fast, privacy-focused, open-source alternative to Google Analytics.
  * [usabilityhub.com](https://usabilityhub.com/) — Test designs and mockups on real people and track visitors. Free for one user, unlimited tests
  * [Userbird](https://userbird.com) - Google Analytics alternative with heatmaps, session recordings and revenue tracking.

**[⬆️ Back to Top](#table-of-contents)**

## Visitor Session Recording

  * [FullStory.com](https://www.fullstory.com) — 1,000 sessions/month with one month data retention and three user seats. More information [here](https://help.fullstory.com/hc/en-us/articles/360020623354-FullStory-Free-Edition).
  * [howuku.com](https://howuku.com) — Track user interaction, engagement, and event. Free for up to 5,000 visits/month
  * [inspectlet.com](https://www.inspectlet.com/) — 2,500 sessions/month free for one website
  * [LogRocket.com](https://www.logrocket.com) - 1,000 sessions/month with 30-day retention, error tracking, live mode
  * [Microsoft Clarity](https://clarity.microsoft.com/) - Session recording completely free with "no traffic limits", no project limits, and no sampling
  * [mouseflow.com](https://mouseflow.com/) — 500 sessions/month free for one website
  * [OpenReplay.com](https://www.openreplay.com) - Open-source session replay with dev tools for bug reproduction, live session for real-time support, and product analytics suite. One thousand sessions/month with access to all features and 7-day retention.
  * [Reactflow.com](https://www.reactflow.com/) — Per site: 1,000 pages views/day, three heatmaps, three widgets, free bug tracking
  * [smartlook.com](https://www.smartlook.com/) — free packages for web and mobile apps (1500 sessions/month), three heatmaps, one funnel, 1-month data history
  * [UXtweak.com](https://www.uxtweak.com/) — Record and watch how visitors use your website or app. Free unlimited time for small projects

**[⬆️ Back to Top](#table-of-contents)**

## International Mobile Number Verification API and SDK

  * [numverify](https://numverify.com/) — Global phone number validation and lookup JSON API. 100 API requests/month
  * [veriphone](https://veriphone.io/) — Global phone number verification in a free, fast, reliable JSON API. 1000 requests/month

**[⬆️ Back to Top](#table-of-contents)**

## Payment and Billing Integration

  * [Adapty.io](https://adapty.io/) – One-stop solution with open-source SDK for mobile in-app subscription integration to iOS, Android, React Native, Flutter, Unity, or web app. Free up to $10k monthly revenue.
  * [CoinMarketCap](https://coinmarketcap.com/api/) — Provides cryptocurrency market data including the latest crypto and fiat currency exchange rates. The free tier offers 10K call credits/month.
  * [Currencyapi](https://currencyapi.com) — Free currency conversion and exchange rate data API. Free 300 requests per month, 10 requests per minute for private use.
  * [CurrencyApi](https://currencyapi.net/) — Live Currency Rates for Physical and Cryptocurrencies, delivered in JSON and XML. The free tier offers 1,250 API requests/month.
  * [CurrencyFreaks](https://currencyfreaks.com/) — Provides current and historical currency exchange rates. Free DEVELOPER plan available with 1000 requests/month.
  * [currencylayer](https://currencylayer.com/) — Reliable Exchange Rates and Currency Conversion for your Business, 100 API requests/month free.
  * [exchangerate-api.com](https://www.exchangerate-api.com) - An easy-to-use currency conversion JSON API. The free tier updates once per day with a limit of 1,500 requests/month.
  * [FraudLabsPRO](https://www.fraudlabspro.com) — Help merchants to prevent payment fraud and chargebacks. Free Micro Plan available with 500 queries/month.
  * [FxRatesAPI](https://fxratesapi.com) — Provides real-time and historical exchange rates. The free tier requires attribution.
  * [Moesif API Monetization](https://www.moesif.com/) - Generate revenue from APIs via usage-based billing. Connect to Stripe, Chargebee, etc. The free tier offers 30,000 events/month.
  * [ParityVend](https://www.ambeteco.com/ParityVend/) – Automatically adjust pricing based on visitor location to expand your business globally and reach new markets (purchasing power parity). The free plan includes 7,500 API requests/month.
  * [Qonversion](http://qonversion.io/) - All-in-one cross-platform subscription management platform offering analytics, A/B testing, Apple Search Ads, remote configs, and growth tools for optimizing in-app purchases and monetization. Compatible with iOS, Android, React Native, Flutter, Unity, Cordova, Stripe, and web. Free up to $10k in monthly tracked revenue.
  * [RevenueCat](https://www.revenuecat.com/) — Hosted backend for in-app purchases and subscriptions (iOS and Android). Free up to $2.5k/mo in tracked revenue.
  * [vatlayer](https://vatlayer.com/) — Instant VAT number validation and EU VAT rates API, free 100 API requests/month

**[⬆️ Back to Top](#table-of-contents)**

## Docker Related

  * [Container Registry Service](https://container-registry.com/) - Harbor based Container Management Solution. The free tier offers 1 GB of storage for private repositories.
  * [Docker Hub](https://hub.docker.com) — One free private repository and unlimited public repositories to build and store Docker images
  * [Play with Docker](https://labs.play-with-docker.com/) — A simple, interactive, fun playground to learn Docker.
  * [quay.io](https://quay.io/) — Build and store container images with unlimited free public repositories
  * [ttl.sh](https://ttl.sh/) - Anonymous & ephemeral Docker image registry

**[⬆️ Back to Top](#table-of-contents)**

## Dev Blogging Sites

  * [AyeDot](https://ayedot.com/) — Share your ideas, knowledge, and stories with the world for Free in the form of Modern multimedia short-format Miniblogs.
  * [BearBlog](https://bearblog.dev/) - Minimalist, Markdown-powered blog and website builder.
  * [Dev.to](https://dev.to/) - Where programmers share ideas and help each other grow.
  * [Hashnode](https://hashnode.com/) — Hassle-free Blogging Software for Developers!.
  * [Medium](https://medium.com/) — Get more thoughtful about what matters to you.
  * [JustBlogged](https://justblogged.com) — Free blogging platform with custom domain support, and fast global performance.

**[⬆️ Back to Top](#table-of-contents)**

## Commenting Platforms

  * [GraphComment](https://graphcomment.com/) - GraphComment is a comments platform that helps you build an active community from the website’s audience.
  * [IntenseDebate](https://intensedebate.com/) - A feature-rich comment system for WordPress, Tumblr, Blogger, and many other website platforms.
  * [Remarkbox](https://www.remarkbox.com/) - Open source hosted comments platform, pay what you can for "One moderator on a few domains with complete control over behavior & appearance"
  * [Utterances](https://utteranc.es/) - A lightweight comments widget built on GitHub issues. Use GitHub issues for blog comments, wiki pages, and more!

**[⬆️ Back to Top](#table-of-contents)**

## Screenshot APIs

  * [ApiFlash](https://apiflash.com) — A screenshot API based on Aws Lambda and Chrome. Handles full page, captures timing, and viewport dimensions.
  * [microlink.io](https://microlink.io/) – It turns any website into data such as metatags normalization, beauty link previews, scraping capabilities, or screenshots as a service. 250 requests/day every day free.
  * [PhantomJsCloud](https://PhantomJsCloud.com) — Browser automation and page rendering.  Free Tier offers up to 500 pages/day.  Free Tier since 2017.
  * [screenshotbase.com](https://screenshotbase.com) - 300 free screenshots / month. Take screenshots from any url. Fast, free & scalable.
  * [screenshotlayer.com](https://screenshotlayer.com/) — Capture highly customizable snapshots of any website. Free 100 snapshots/month
  * [screenshotmachine.com](https://www.screenshotmachine.com/) — Capture 100 snapshots/month, png, gif and jpg, including full-length captures, not only home page
  * [thumbnail.ws](https://thumbnail.ws) — API for generating thumbnails of websites. Free 1,000 requests/month.

**[⬆️ Back to Top](#table-of-contents)**

## Flutter Related and Building IOS Apps without Mac

  * [CodeMagic](https://codemagic.io/) - Codemagic is a fully hosted and managed CI/CD for mobile apps. You can build, test, and deploy with a GUI-based CI/CD tool. The free tier offers 500 free minutes/month and a Mac Mini instance with 2.3 GHz and 8 GB of RAM.
  * [FlutLab](https://flutlab.io/) - FlutLab is a modern Flutter online IDE and the best place to create, debug, and build cross-platform projects. Build iOS (Without a Mac) and Android apps with Flutter.
  * [FlutterFlow](https://flutterflow.io/) -  FlutterFlow is a browser-based drag-and-drop interface to build mobile app using flutter.

**[⬆️ Back to Top](#table-of-contents)**

## Browser-based hardware emulation written in Javascript

  * [Jor1k](https://s-macke.github.io/jor1k/demos/main.html) —  an OpenRISC virtual machine capable of running Linux with network support.
  * [JsLinux](https://bellard.org/jslinux) — a really fast x86 virtual machine capable of running Linux and Windows 2k.
  * [v86](https://copy.sh/v86) — an x86 virtual machine capable of running Linux and other OS directly into the browser.

**[⬆️ Back to Top](#table-of-contents)**

## Privacy Management

  * [Bearer](https://www.bearer.sh/) - Helps implement privacy by design via audits and continuous workflows so that organizations comply with GDPR and other regulations. The free tier is limited to smaller teams and the SaaS version only.
  * [Concord](https://www.concord.tech/) - Full data privacy platform, including consent management, privacy request handling (DSARs), and data mapping. Free tier includes core consent management features and they also provide a more advanced plan for free to verified open source projects.
  * [Cookiefirst](https://cookiefirst.com/) - Cookie banners, auditing, and multi-language consent management solution. The free tier offers a one-time scan and a single banner.
  * [Iubenda](https://www.iubenda.com/) - Privacy and cookie policies and consent management. The free tier offers limited privacy and cookie policy as well as cookie banners.
  * [Ketch](https://www.ketch.com/) - Consent management and privacy framework tool. The free tier offers most features with a limited visitor count.

**[⬆️ Back to Top](#table-of-contents)**

## Miscellaneous

  * [BackgroundStyler.com](https://backgroundstyler.com) - Create aesthetic screenshots of your code, text or images to share on social media.
  * [Base64 decoder/encoder](https://devpal.co/base64-decode/) — Online free tool for decoding & encoding data.
  * [BinShare.net](https://binshare.net) - Create & share code or binaries. Available to share as a beautiful image e.g. for Twitter / Facebook post or as a link e.g. for chats or forums.
  * [Blynk](https://blynk.io) — A SaaS with API to control, build & evaluate IoT devices. Free Developer Plan with 5 devices, Free Cloud & data storage. Mobile Apps are also available.
  * [Bricks Note Calculator](https://free.getbricks.app/) - a note-taking app (PWA) with a powerful built-in multiline calculator.
  * [Carbon.now.sh](https://carbon.now.sh) - create and share code snippets in an aesthetic screenshot-like image format. Usually used to aesthetically share/show off code snippets on Twitter or blog posts.
  * [Code Time](https://www.software.com/code-time) - an extension for time-tracking and coding metrics in VS Code, Atom, IntelliJ, Sublime Text, and more.
  * [Codepng](https://www.codepng.app) - Create excellent snapshots from your source code to share on social media.
  * [CodeToImage](https://codetoimage.com/) - Create screenshots of code or text to share on social media.
  * [cron-job.org](https://cron-job.org) - Online cronjobs service. Unlimited jobs are free of charge.
  * [Cronhooks](https://cronhooks.io/) - Schedule on-time or recurring webhooks. The free plan allows 5 ad-hoc schedules.
  * [datelist.io](https://datelist.io) - Online booking / appointment scheduling system. Free up to 5 bookings per month, includes 1 calendar
  * [Domain Forward](https://domain-forward.com/) - A straightforward tool to forward any URL or Domain. Free up to 5 domains and 200k requests per month.
  * [Exif Editor](https://exifeditor.io/) — View, Edit, Scrub, Analyze image/photo metadata in-browser instantly - including GPS location and metadata.
  * [Format Express](https://www.format-express.dev) - Instant online format for JSON / XML / SQL.
  * [FOSSA](https://fossa.com/) - Scalable, end-to-end management for third-party code, license compliance and vulnerabilities.
  * [Hook Relay](https://www.hookrelay.dev/) - Add webhook support to your app without the hassles: done-for-you queueing, retries with backoff, and logging. The free plan has 100 deliveries per day, 14-day retention, and 3 hook endpoints.
  * [Hosting Checker](https://hostingchecker.co) - Check hosting information such as ASN, ISP, location and more for any domain, website or IP address. Also includes multiple hosting and DNS-related tools.
  * [newreleases.io](https://newreleases.io/) - Receive notifications on email, Slack, Telegram, Discord, and custom webhooks for new releases from GitHub, GitLab, Bitbucket, Python PyPI, Java Maven, Node.js NPM, Node.js Yarn, Ruby Gems, PHP Packagist, .NET NuGet, Rust Cargo and Docker Hub.
  * [OnlineExifViewer](https://onlineexifviewer.com/) — View EXIF data online instantly for a photo including GPS location and metadata.
  * [PDFMonkey](https://www.pdfmonkey.io/) — Manage PDF templates in a dashboard, call the API with dynamic data, and download your PDF. Offers 300 free documents per month.
  * [Pika Code Screenshots](https://pika.style/templates/code-image) — Create beautiful, customizable screenshots from code snippets and VSCode using the extension.
  * [QuickType.io](https://quicktype.io/) - Quickly auto-generate models/class/type/interface and serializers from JSON, schema, and GraphQL for working with data quickly & safely in any programming language. Convert JSON into gorgeous, typesafe code in any language.
  * [RandomKeygen](https://randomkeygen.com/) - A free mobile-friendly tool that offers a variety of randomly generated keys and passwords you can use to secure any application, service, or device.
  * [ray.so](https://ray.so/) - Create beautiful images of your code snippets.
  * [readme.com](https://readme.com/) — Beautiful documentation made easy, free for Open Source.
  * [redirect.pizza](https://redirect.pizza/) - Easily manage redirects with HTTPS support. The free plan includes 10 sources and 100,000 hits per month.
  * [redirection.io](https://redirection.io/) — SaaS tool for managing HTTP redirections for businesses, marketing and SEO.
  * [Renamer.ai](https://renamer.ai) — AI-powered file renaming tool with OCR, metadata extraction, and automation for 20+ languages. Free tier: 15 files/month, including desktop app, batch rename, auto-rename, and normal support.
  * [ReqBin](https://reqbin.com/) — Post HTTP Requests Online. Popular Request Methods include GET, POST, PUT, DELETE, and HEAD. Supports Headers and Token Authentication. Includes a basic login system for saving your requests.
  * [Smartcar API](https://smartcar.com) - An API for cars to locate, get fuel tank, battery levels, odometer, unlock/lock doors, etc.
  * [snappify](https://snappify.com) - Enables developers to create stunning visuals. From beautiful code snippets to fully fletched technical presentations. The free plan includes up to 3 snaps at once with unlimited downloads and 5 AI-powered code explanations per month.
  * [Sunrise and Sunset](https://sunrisesunset.io/api/) - Get sunrise and sunset times for a given longitude and latitude.
  * [superfeedr.com](https://superfeedr.com/) — Real-time PubSubHubbub compliant feeds, export, analytics. Free with less customization
  * [SurveyMonkey.com](https://www.surveymonkey.com) — Create online surveys. Analyze the results online. The free plan allows only 10 questions and 100 responses per survey.
  * [UUID Generator](https://newuuid.com/) - Generate UUID v1, UUID v4, UUID v7, GUID, Nil UUIDs, CUID v1/v2, NanoID, and ULID instantly with enterprise-grade
  * [Versionfeeds](https://versionfeeds.com) — Custom RSS feeds for releases of your favorite software. Have the latest versions of your programming languages, libraries, or loved tools in one feed. (The first 3 feeds are free)
  * [videoinu](https://videoinu.com) — Create and edit screen recordings and other videos online.
  * [Volume Shader BM](https://volumeshaderbm.org) — Free browser-based GPU benchmark (WebGL). Helps developers test and compare shader performance reproducibly across browsers and devices.
  * [Webacus](https://webacus.dev) — Access a wide range of free developer tools for encoding, decoding, and data manipulation.
  * [XKit](https://xkit.io) — A collection of free online tools designed to make life easier for developers, students, and everyday users. Include a wide range of Developer tools, Diff/Compare tools, Calculators, Converters and Generators.
  performance and security

**[⬆️ Back to Top](#table-of-contents)**

## Remote Desktop Tools

  * [AnyDesk](https://anydesk.com) —  Free for 3 devices, no limits on the number and duration of sessions
  * [Getscreen.me](https://getscreen.me) —  Free for 2 devices, no limits on the number and duration of sessions
  * [RemSupp](https://remsupp.com) — On-demand support and permanent access to devices (2 sessions/day for free)
  * [RustDesk](https://rustdesk.com/) - Open source virtual/remote desktop infrastructure for everyone!

**[⬆️ Back to Top](#table-of-contents)**

## Game Development

  * [3Dassets.one](https://3dassets.one/) - Over 8,000 free/paid 3D models, and PBR materials for making textures.
  * [ArtStation](https://www.artstation.com/) - MarketPlace for Free/Paid 2D, 3D assets & audios, icons, tile sets, game kits. Also, It can be used for showcasing your art portfolio.
  * [CraftPix](https://craftpix.net) — Free/Paid assets like 2D, 3D, Audio, GUI, backgrounds, icons, tile sets, game kits.
  * [Freesound](https://freesound.org/) - Free collaborative sound library offerer with different CC licenses.
  * [Game Icons](https://game-icons.net/) - Free styleable SVG/PNG icons provided under a CC-BY license.
  * [GameDevMarket](https://gamedevmarket.net) — Free/Paid assets like 2D, 3D, Audio, GUI.
  * [Gamefresco.com](https://gamefresco.com/) — Discover, collect, and share free game assets from game artists everywhere.
  * [itch.io](https://itch.io/game-assets) — Free/Paid assets like sprites, tile sets, and character packs.
  * [Kenney](https://www.kenney.nl/assets/) - Free (CC0 1.0 Universal licensed) 2D, 3D, Audio, and UI game assets.
  * [LoSpec](https://lospec.com/) — Online tools for creating pixel art and other restrictive digital art, lots of tutorials/pallet list available to choose from for your games
  * [OpenGameArt](https://opengameart.org) — OpenSource Game Assets like music, sounds, sprites, and gifs.
  * [Poliigon](https://www.poliigon.com/) - Free and paid textures (with variable resolution), models, HDRIs, and brushes. Offers free plugins to export to software like Blender.
  * [Poly Pizza](https://poly.pizza/) - Free low poly 3D assets

**[⬆️ Back to Top](#table-of-contents)**

## Other Free Resources

  * [360Converter](https://www.360converter.com/) - Free tier useful website to convert: Video to Text && Audio to Text && Speech to Text && Real-time Audio to Text && YouTube Video to Text && add Video Subtitle. Maybe it will be helpful in a short video conversion or in a short youtube tutorial:)
  * [AdminMart](https://adminmart.com/) — High-Quality Free and Premium Admin Dashboard and Website Templates created with Angular, Bootstrap, React, VueJs, NextJS, and NuxtJS!
  * [Buttons Generator](https://markodenic.com/tools/buttons-generator/) — 100+ buttons you can use in your project.
  * [ElevateAI](https://www.elevateai.com) - Get up to 200 hours of audio transcription for free every month.
  * [Framacloud](https://degooglisons-internet.org/en/) — A list of Free/Libre Open Source Software and SaaS by the French non-profit [Framasoft](https://framasoft.org/en/).
  * [Free Code Tools](https://freecodetools.org/) — Effective code tools which are 100% free. Markdown editor, Code minifier/beautifier, QR code generator, Open Graph Generator, Twitter card Generator, and more.
  * [get.localhost.direct](https://get.localhost.direct) — A better `*.localhost.direct` Wildcard public CA signed SSL cert for localhost development with sub-domain support
  * [GitHub Education](https://education.github.com/pack) — Collection of free services for students. Registration required.
  * [Glob tester](https://globster.xyz/) — A website that allows you to design and test glob patterns. It also provides resources to learn glob patterns.
  * [It tools](https://it-tools.tech/) - Useful tools for developer and people working in IT.
  * [JSON Viewer Tool](https://jsonviewertool.com/) – View, format, validate, minify, and convert JSON data directly in the browser (no API key required).
  * [Killer Coda](https://killercoda.com/)  - Interactive playground in your browser to study Linux, Kubernetes, Containers, Programming, DevOps, Networking
  * [Kody Tools](https://www.kodytools.com/dev-tools) — 100+ dev tools including formatter, minifier, and converter.
  * [Markdown Tools](https://markdowntools.com) - Tools for converting HTML, CSVs, PDFs, JSON, and Excel files to and from Markdown
  * [Microsoft 365 Developer Program](https://developer.microsoft.com/microsoft-365/dev-program) — Get a free sandbox, tools, and other resources you need to build solutions for the Microsoft 365 platform. The subscription is a 90-day [Microsoft 365 E5 Subscription](https://www.microsoft.com/microsoft-365/enterprise/e5) (Windows excluded) which is renewable. It is renewed if you're active in development(measured using telemetry data & algorithms).
  * [MySQL Visual Explain](https://mysqlexplain.com) - Easy-to-understand and free MySQL EXPLAIN output visualizer to optimize slow queries.
  * [PageTools](https://pagetools.co/) - Offers a suite of forever free AI-powered tools to help you generate essential website policies, create social media bios, posts and web pages with a simple one-click interface.
  * [Pyrexp](https://pythonium.net/regex) — Free web-based regex tester and visualizer for debugging regular expressions.
  * [RedHat for Developers](https://developers.redhat.com) — Free access to Red Hat products including RHEL, OpenShift, CodeReady, etc. exclusively for developers. Individual plan only. Free e-books are also offered for reference.
  * [regex101](https://regex101.com/) — Free this website allows you to test and debug regular expressions (regex). It provides a regex editor and tester, as well as helpful documentation and resources for learning regex.
  * [sandbox.httpsms.com](https://sandbox.httpsms.com) — Send and receive test SMS messages for free.
  * [SimpleBackups.com](https://simplebackups.com/) — Backup automation service for servers and databases (MySQL, PostgreSQL, MongoDB) stored directly into cloud storage providers (AWS, DigitalOcean, and Backblaze). Provides a free plan for 1 backup.
  * [SimpleRestore](https://simplerestore.io) - Hassle-free MySQL backup restoration. Restore MySQL backups to any remote database without code or a server.
  * [SnapShooter](https://snapshooter.com/) — Backup solution for DigitalOcean, AWS, LightSail, Hetzner, and Exoscale, with support for direct database, file system and application backups to s3 based storage. Provides a free plan with daily backups for one resource.
  * [Table Format Converter](https://www.tableformatconverter.com) - A free tool to convert table data to different formats, such as CSV, HTML, JSON, Markdown and more.
  * [Themeselection](https://themeselection.com/) — Selected high quality, modern design, professional and easy-to-use Free Admin Dashboard Template,
  * [ToolsHref](https://toolshref.com) - A suite of free developer utilities including Java code generation (JSON-to-POJO, cURL-to-Java), static analysis, and DevOps config builders (Docker, K8s, Nginx).
  * [Utils.fun](https://utils.fun/en) — All offline daily and development tools based on the browser's computing power, including watermark generation, screen recording, encoding and decoding, encryption and decryption, and code formatting, are completely free and do not upload any data to the cloud for processing.
  * [Wikimint Developer](https://developer.wikimint.com/p/tools.html) - Always free tools for web developers that includes CSS minify unminify, image optimizer, image resizer, case convertor, CSS validator, JavaScript compiler, HTML editor, etc.
  * [WrapPixel](https://www.wrappixel.com/) — Download High Quality Free and Premium Admin dashboard template created with Angular, React, VueJs, NextJS, and NuxtJS!
HTML Themes and UI Kits to create your applications faster!

**[⬆️ Back to Top](#table-of-contents)**
