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
  * [Vagrant Related](#vagrant-related)
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

**[⬆️ Back to Top](#table-of-contents)**

## Cloud management solutions

  * [Brainboard](https://www.brainboard.co) - Collaborative solution to visually build and manage cloud infrastructures from end-to-end.
  * [Cloud 66](https://www.cloud66.com/) - Free for personal projects (includes one deployment server, one static site), Cloud 66 gives you everything you need to build, deploy, and grow your applications on any cloud without the headache of the “server stuff.”.
  * [Pulumi](https://www.pulumi.com/) — Modern infrastructure as a code platform that allows you to use familiar programming languages and tools to build, deploy, and manage cloud infrastructure.
  * [terraform.io](https://www.terraform.io/) — Terraform Cloud. Free remote state management and team collaboration for up to 500 resources.
  * [scalr.com](https://scalr.com/) - Scalr is a Terraform Automation and COllaboration (TACO) product used to better collaboration and automation on infrastructure and configurations managed by Terraform. Full Terraform CLI support, OPA integration, and a hierarchical configuration model. No SSO tax. All features are included. Use up to 50 runs/month for free.
  * [deployment.io](https://deployment.io) - Deployment.io helps developers automate deployments on AWS. On our free tier, a developer (single user) can deploy unlimited static sites, web services, and environments. We provide 20 job executions free per month with previews and auto-deploys included in the free tier.

**[⬆️ Back to Top](#table-of-contents)**

## Source Code Repos

  * [Bitbucket](https://bitbucket.org/) — Unlimited public and private Git repos for up to 5 users with Pipelines for CI/CD
  * [chiselapp.com](https://chiselapp.com/) — Unlimited public and private Fossil repositories
  * [codebasehq.com](https://www.codebasehq.com/) — One free project with 100 MB space and two users
  * [Codeberg](https://codeberg.org/) — Unlimited public and private Git repos for free and open-source projects (with unlimited collaborators). Powered by [Forgejo](https://forgejo.org/). Static website hosting with [Codeberg Pages](https://codeberg.page/). CI/CD hosting with [Codeberg's CI](https://docs.codeberg.org/ci/). Translating hosting with [Codeberg Translate](https://translate.codeberg.org/). Includes Package and Container hosting, Project management, and Issue Tracking
  * [GitGud](https://gitgud.io) — Unlimited private and public repositories. Free forever. Powered by GitLab & Sapphire. CI/CD not provided.
  * [GitHub](https://github.com/) — Unlimited public repositories and unlimited private repositories (with unlimited collaborators). Includes CI/CD, Development Environment, Static Hosting, Package and Container hosting, Project management and AI Copilot
  * [gitlab.com](https://about.gitlab.com/) — Unlimited public and private Git repos with up to 5 collaborators. Includes CI/CD, Static Hosting, Container Registry, Project Management and Issue Tracking
  * [framagit.org](https://framagit.org/) — Framagit is the software forge of Framasoft based on the Gitlab software includes CI, Static Pages, Project pages and Issue tracking.
  * [heptapod.net](https://foss.heptapod.net/) — Heptapod is a friendly fork of GitLab Community Edition providing support for Mercurial
  * [ionicframework.com](https://ionicframework.com/appflow) - Repo and tools to develop applications with Ionic; also you have an ionic repo
  * [NotABug](https://notabug.org) — NotABug.org is a free-software code collaboration platform for freely licensed projects, Git-based
  * [OSDN](https://osdn.net/) - OSDN.net is a free-of-charge service for open-source software developers, offering SVN/Git/Mercurial/Bazaar/CVS repositories.
  * [Pagure.io](https://pagure.io) — Pagure.io is a free and open source software code collaboration platform for FOSS-licensed projects, Git-based
  * [perforce.com](https://www.perforce.com/products/helix-teamhub) — Free 1GB Cloud and  Git, Mercurial, or SVN repositories.
  * [pijul.com](https://pijul.com/) - Unlimited free and open source distributed version control system. Its distinctive feature is based on a sound theory of patches, which makes it easy to learn, use, and distribute. Solves many problems of git/hg/svn/darcs.
  * [plasticscm.com](https://plasticscm.com/) — Free for individuals, OSS, and nonprofit organizations
  * [projectlocker.com](https://projectlocker.com) — One free private project (Git and Subversion) with 50 MB of space
  * [RocketGit](https://rocketgit.com) — Repository Hosting based on Git. Unlimited Public and private repositories.
  * [savannah.gnu.org](https://savannah.gnu.org/) - Serves as a collaborative software development management system for free Software projects (for GNU Projects)
  * [savannah.nongnu.org](https://savannah.nongnu.org/) - Serves as a collaborative software development management system for free Software projects (for non-GNU projects)

**[⬆️ Back to Top](#table-of-contents)**

## APIs, Data, and ML

  * [JSONGrid](https://jsongrid.com) - Free tool to Visualize, Edit, Filter complex JSON data into beautiful tabular Grid. Save and Share JSON data over link link.
  * [Zerosheets](https://zerosheets.com) - Turn your Google Sheets spreadsheets into powerful API`s to rapidly develop prototypes, websites, apps and more. 500 requests per month available for free.
  * [JSON to Table](https://jsontotable.org) - Convert JSON into an interactive table for quick viewing, editing, and sharing online.
  * [IP.City](https://ip.city) — 100 Free IP geolocation requests per day
  * [Abstract API](https://www.abstractapi.com) — API suite for various use cases, including IP geolocation, gender detection, or email validation.
  * [Apify](https://www.apify.com/) — Web scraping and automation platform to create an API for any website and extract data. Ready-made scrapers, integrated proxies, and custom solutions. Free plan with $5 platform credits included every month.
  * [APITemplate.io](https://apitemplate.io) - Auto-generate images and PDF documents with a simple API or automation tools like Zapier & Airtable. No CSS/HTML is required. The free plan comes with 50 images/month and three templates.
  * [APIToolkit.io](https://apitoolkit.io) - All the tools you need to fully understand what's going on in your APIs and Backends. With automatic API contract validation and monitoring. The free plan covers servers with up to 10,000 requests per day.
  * [APIVerve](https://apiverve.com) - Get instant access to over 120+ APIs for free, built with quality, consistency, and reliability in mind. The free plan covers up to 50 API Tokens per month. (Possibly taken down, 2025-06-25)
  * [Arize AI](https://arize.com/) - Machine learning observability for model monitoring and root-causing issues such as data quality and performance drift. Free up to two models.
  * [Maxim AI](https://getmaxim.ai/) - Simulate, evaluate, and observe your AI agents. Maxim is an end-to-end evaluation and observability platform, helping teams ship their AI agents reliably and >5x faster. Free forever for indie developers and small teams (3 seats).
  * [Beeceptor](https://beeceptor.com) - Mock a rest API in seconds, fake API response and much more. Free 50 requests per day, public dashboard, open endpoints (anyone with a dashboard link can view submissions and answers).
  * [BigDataCloud](https://www.bigdatacloud.com/) - Provides fast, accurate, and free (Unlimited or up to 10K-50K/month) APIs for modern web like IP Geolocation, Reverse Geocoding, Networking Insights, Email and Phone Validation, Client Info and more.
  * [Browse AI](https://www.browse.ai) — Extracting and monitoring data on the web. 1k credits per month for free, equals 1k concurrent requests.
  * [BrowserCat](https://www.browsercat.com) - Headless browser API for automation, scraping, AI agent web access, image/pdf generation, and more. Free plan with 1k requests per month.
  * [CarAPI.dev](https://carapi.dev) — Comprehensive automotive data API with VIN decoding, stolen vehicle checks, vehicle valuation, inspection data, and more. Free tier includes 100 requests/month across all 9 endpoints.
  * [Calendarific](https://calendarific.com) - Enterprise-grade Public holiday API service for over 200 countries. The free plan includes 500 calls per month.
  * [Canopy](https://www.canopyapi.co/) - GraphQL API for Amazon.com product, search, and category data. The free plan includes 100 calls per month.
  * [Clarifai](https://www.clarifai.com) — Image API for custom face recognition and detection. Able to train AI models. The free plan has 1,000 calls per month.
  * [Cloudmersive](https://cloudmersive.com/) — Utility API platform with full access to expansive API Library including Document Conversion, Virus Scanning, and more with 600 calls/month, North America AZ only, 2.5MB maximum file size.
  * [Colaboratory](https://colab.research.google.com) — Free web-based Python notebook environment with Nvidia Tesla K80 GPU.
  * [CometML](https://www.comet.com/site/) - The MLOps platform for experiment tracking, model production management, model registry, and complete data lineage, covering your workflow from training to production. Free for individuals and academics.
  * [Commerce Layer](https://commercelayer.io) - Composable commerce API that can build, place, and manage orders from any front end. The developer plan allows 100 orders per month and up to 1,000 SKUs for free.
  * [Composio](https://composio.dev/) - Integration platform for AI Agents and LLMs. Integrate over 200+ tools across the agentic internet.
  * [Conversion Tools](https://conversiontools.io/) - Online File Converter for documents, images, video, audio, and eBooks. REST API is available. Libraries for Node.js, PHP, Python. Support files up to 50 GB (for paid plans). The free tier is limited by file size (20MB) and number of conversions (30/Day, 300/Month).
  * [Country-State-City Microservice API](https://country-state-city.rebuscando.info/) - API and Microservice to provides a wide range of information including countries, regions, provinces, cities, postal codes, and much more. The free tier includes up to 100 requests per day.
  * [Coupler](https://www.coupler.io/) - Data integration tool that syncs between apps. It can create live dashboards and reports, transform and manipulate values, and collect and back up insights. The free plan is limited to one user, data connection, data source, and data destination. Also requires manual data refresh.
  * [CraftMyPDF](https://craftmypdf.com) - Auto-Generate PDF documents from reusable templates with a drop-and-drop editor and a simple API. The free plan comes with 100 PDFs/month and three templates.
  * [Crawlbase](https://crawlbase.com/) — Crawl and scrape websites without proxies, infrastructure, or browsers. We solve captchas for you and prevent you from being blocked. The first 1000 calls are free of charge.
  * [CurlHub](https://curlhub.io) — Proxy service for inspecting and debugging API calls. The free plan includes 10,000 requests per month.
  * [CurrencyScoop](https://currencyscoop.com) - Realtime currency data API for fintech apps. The free plan includes 5,000 calls per month.
  * [CustomJS](https://www.customjs.io) - HTML to PDF or PDF to PNG/Text & PDF merging/extraction/merging APIs. Free tier has 600 calls a month.
  * [Cube](https://cube.dev/) - Cube helps data engineers and application developers access data from modern data stores, organize it into consistent definitions, and deliver it to every application. The fastest way to use Cube is with Cube Cloud, which has a free tier limited to 1,000 queries per day.
  * [Data Dead Drop](https://datadeaddrop.com) - Simple, free file sharing. Data self-destroys after access. Upload and download data via the browser or your favorite command line client.
  * [Data Fetcher](https://datafetcher.com) - Connect Airtable to any application or API with no code. Postman-like interface for running API requests in Airtable. Pre-built integrations with dozens of apps. The free plan includes 100 runs per month.
  * [Dataimporter.io](https://www.dataimporter.io) - Tool for connecting, cleaning, and importing data into Salesforce. Free Plan includes up to 20,000 records per month.
  * [Datalore](https://datalore.jetbrains.com) - Python notebooks by Jetbrains. Includes 10 GB of storage and 120 hours of runtime each month.
  * [Data Miner](https://dataminer.io/) - A browser extension (Google Chrome, MS Edge) for data extraction from web pages CSV or Excel. The free plan gives you 500 pages/month.
  * [Datapane](https://datapane.com) - API for building interactive reports in Python and deploying Python scripts and Jupyter Notebooks as self-service tools.
  * [DB-IP](https://db-ip.com/api/free) - Free IP geolocation API with 1k request per IP per day.lite database under the CC-BY 4.0 License is free too.
  * [DB Designer](https://www.dbdesigner.net/) — Cloud-based Database schema design and modeling tool with a free starter plan of 2 Database models and ten tables per model.
  * [DeepAR](https://developer.deepar.ai) — Augmented reality face filters for any platform with one SDK. The free plan provides up to 10 monthly active users (MAU) and tracks up to 4 faces
  * [Deepnote](https://deepnote.com) - A new data science notebook. Jupyter is compatible with real-time collaboration and running in the cloud. The free tier includes unlimited personal projects, unlimited basic machines with 5GB RAM and 2vCPU, and teams with up to 3 editors.
  * [Disease.sh](https://disease.sh/) — A free API providing accurate data for building the Covid-19 related useful Apps.
  * [Doczilla](https://www.doczilla.app/) — SaaS API empowering the generation of screenshots or PDFs directly from HTML/CSS/JS code. The free plan allows 250 documents month.
  * [Doppio](https://doppio.sh/) — Managed API to generate and privately store PDFs and Screenshots using top rendering technology. The free plan allows 400 PDFs and Screenshots per month.
  * [drawDB](https://drawdb.app/) — Free and open-source online database diagram editor with no signup required.
  * [dreamfactory.com](https://dreamfactory.com/) — Open source REST API backend for mobile, web, and IoT applications. Hook up any SQL/NoSQL database, file storage system, or external service, and it instantly creates a comprehensive REST API platform with live documentation and user management.
  * [Duply.co](https://duply.co) — Create dynamic images from API & URL, design template once and reuse it. The free tier offers 20 free credits.
  * [DynamicDocs](https://advicement.io) - Generate PDF documents with JSON to PDF API based on LaTeX templates. The free plan allows 50 API calls per month and access to a library of templates.
  * [Efemarai](https://efemarai.com) - Testing and debugging platform for ML models and data. Visualize any computational graph. Free local use.
  * [ERD Lab](https://www.erdlab.io) —  Free cloud-based entity relationship diagram (ERD) tool made for developers. Free trial includes 2 projecs with 10 tables each.
  * [ExtendsClass](https://extendsclass.com/rest-client-online.html) - Free web-based HTTP client to send HTTP requests.
  * [Export SDK](https://exportsdk.com) - PDF generator API with drag-and-drop template editor that provides an SDK and no-code integrations. The free plan has 250 monthly pages, unlimited users, and three templates.
  * [file.coffee](https://file.coffee/) - A platform where you can store up to 15MB/file (30/MB file with an account).
  * [Financial Data](https://financialdata.net/) - Stock market and financial data API. Free plan allows 300 requests per day.
  * [FormatJSONOnline.com](https://formatjsononline.com) - A free, browser-based tool to format, validate,compare and minify JSON data instantly.
  * [FraudLabs Pro](https://www.fraudlabspro.com) — Screen an order transaction for credit card payment fraud. This REST API will detect all possible fraud traits based on the input parameters of an order. The Free Micro plan has 500 transactions per month.
  * [GeoDataSource](https://www.geodatasource.com) — Location search service looks up city names using latitude and longitude coordinates. Free API queries up to 500 times per month.
  * [Geolocated.io](https://geolocated.io) — IP Geolocation API with multi-continent servers, offering a free plan with 2,000 requests per day.
  * [Glitterly](https://glitterly.app/) - Programmatically generate dynamic images from base templates. Restful API and nocode integrations. The free tier comes with 50 images/month and five templates.
  * [Hex](https://hex.tech/) - a collaborative data platform for notebooks, data apps, and knowledge libraries. Free community tier with up to five projects.
  * [Hook0](https://www.hook0.com/) - Hook0 is an open-source Webhooks-as-a-service (WaaS) that makes it easy for online products to provide webhooks. Dispatch up to 100 events/day with seven days of history retention for free.
  * [Hoppscotch](https://hoppscotch.io) - A free, fast, and beautiful API request builder.
  * [huggingface.co](https://huggingface.co) - Build, train, and deploy NLP models for Pytorch, TensorFlow, and JAX. Free up to 30k input characters/mo.
  * [Hybiscus](https://hybiscus.dev/) - Build pdf reports using a simple declarative API. The 14-day free tier includes 50 single-page reports with the ability to customize color palettes and fonts.
  * [Invantive Cloud](https://cloud.invantive.com/) — Access over 70 (cloud)platforms such as Exact Online, Twinfield, ActiveCampaign or Visma using Invantive SQL or OData4 (typically Power BI or Power Query). Includes data replication and exchange. Free plan for developers and implementation consultants. Free for specific platforms with limitations in data volumes.
  * [ipaddress.sh](https://ipaddress.sh) — Simple service to get a public IP address in different [formats](https://about.ipaddress.sh/).
  * [ip-api](https://ip-api.com) — IP Geolocation API, Free for non-commercial use, no API key required, limited to 45 req/minute from the same IP address for the free plan.
  * [ipbase.com](https://ipbase.com) - IP Geolocation API - Forever free plan that spans 150 monthly requests.
  * [IP Geolocation](https://ipgeolocation.io/) — IP Geolocation API - Forever free plan for developers with a 1,000 requests per day limit.
  * [IP Geolocation API](https://www.abstractapi.com/ip-geolocation-api) — IP Geolocation API from Abstract - Allows 1,000 free requests.
  * [IPLocate](https://www.iplocate.io) — IP Geolocation API, free up to 1,000 requests/day. Includes proxy/VPN/hosting detection, ASN data, IP to Company, and more. IPLocate also offers free downloadable IP to Country and IP to ASN databases in CSV or GeoIP-compatible MMDB formats.
  * [IP2Location](https://www.ip2location.com) — Freemium IP geolocation service. LITE database is available for free download. Import the database in the server and perform a local query to determine the city, coordinates, and ISP information.
  * [IP2Location.io](https://www.ip2location.io/) — Freemium, fast, and reliable IP geolocation API. Get data like city, coordinates, ISP, ASN, AS data and more. The free plan includes 50k credits per month. IP2Location.io also offers 500 free WHOIS and hosted domain lookups per month. See domain registration details and find domains hosted on a specific IP. Upgrade to a paid plan for more features.
  * [ipapi](https://ipapi.co/) - IP Address Location API by Kloudend, Inc - A reliable geolocation API built on AWS, trusted by Fortune 500. The free tier offers 30k lookups/month (1k/day) without signup.
  * [ipapi.is](https://ipapi.is/) - A reliable IP Address API from Developers for Developers with the best Hosting Detection capabilities that exist. The free plan offers 1000 lookups without signup.
  * [IPinfo](https://ipinfo.io/) — Fast, accurate, and free (up to 50k/month) IP address data API. Offers APIs with details on geolocation, companies, carriers, IP ranges, domains, abuse contacts, and more. All paid APIs can be trialed for free.
  * [IPQuery](https://ipquery.io) — Unlimited IP API for developers, no ratelimits, or pricing.
  * [IPTrace](https://iptrace.io) — An embarrassingly simple API that provides your business with reliable and helpful IP geolocation data with 50,000 free lookups per month.
  * [JSON2Video](https://json2video.com) - A video editing API to automate video marketing and social media videos, programmatically or with no code.
  * [JSON IP](https://getjsonip.com) — Returns the Public IP address of the client it is requested from. No registration is required for the free tier. Using CORS, data can be requested using client-side JS directly from the browser. Useful for services monitoring change in client and server IPs. Unlimited Requests.
  * [JSON Serve](https://jsonserve.com/) — A free service that helps developers to store JSON objects and use that JSON as a REST API in their app.
  * [JSONing](https://jsoning.com/api/) — Create a fake REST API from a JSON object, and customize HTTP status codes, headers, and response bodies.
  * [JSONSwiss](https://www.jsonswiss.com/) - JSONSwiss is a powerful online JSON viewer, editor, and validator. Format, visualize, search, and manipulate JSON data with AI-powered repair, tree view, table view, code generation in 12+ programming languages, convert json to csv, xml, yaml, properties and more.
  * [konghq.com](https://konghq.com/) — API Marketplace and powerful private and public API tools. With the free tier, some features such as monitoring, alerting, and support, are limited.
  * [Kreya](https://kreya.app) — Free gRPC GUI client to call and test gRPC APIs. Can import gRPC APIs via server reflection.
  * [Lightly](https://www.lightly.ai/) — Improve your machine-learning models by using the correct data. Use datasets of up to 1000 samples for free.
  * [LoginLlama](https://loginllama.app) - A login security API to detect fraudulent and suspicious logins and notify your customers. Free for 1,000 logins per month.
  * [MailboxValidator](https://www.mailboxvalidator.com) — Email verification service using real mail server connection to confirm valid email. The free API plan has 100 verifications per month.
  * [Market Data API](https://www.marketdata.app) - Provides real-time and historical financial data for stocks, options, mutual funds, and more. The Free Forever API tier allows for 100 daily API requests at no charge.
  * [Meteosource Weather API](https://www.meteosource.com/) — global weather API for current and forecasted weather data. Forecasts are based on a machine learning combination of more weather models to achieve better accuracy. The free plan comes with 400 calls per day.
  * [microlink.io](https://microlink.io/) – It turns any website into data such as metatags normalization, beauty link previews, scraping capabilities, or screenshots as a service. 50 requests per day, every day free.
  * [Mindee](https://developers.mindee.com) – Mindee is a powerful OCR software and an API-first platform that helps developers automate applications' workflows by standardizing the document processing layer through data recognition for key information using computer vision and machine learning. The free tier offers 500 pages per month.
  * [Mintlify](https://mintlify.com) — Modern standard for API documentation. Beautiful and easy-to-maintain UI components, in-app search, and interactive playground. Free for 1 editor.
  * [MockAPI](https://www.mockapi.io/) — MockAPI is a simple tool that lets you quickly mock up APIs, generate custom data, and perform operations using a RESTful interface. MockAPI is meant to be a prototyping/testing/learning tool. One project/2 resources per project for free.
  * [Mockfly](https://www.mockfly.dev/) — Mockfly is a trusted development tool for API mocking and feature flag management. Quickly generate and control mock APIs with an intuitive interface. The free tier offers 500 requests per day.
  * [Mocki](https://mocki.io) - A tool that lets you create mock GraphQL and REST APIs synced to a GitHub repository. Simple REST APIs are free to develop and use without signup.
  * [Mocko.dev](https://mocko.dev/) — Proxy your API, choose which endpoints to mock in the cloud and inspect traffic, for free. Speed up your development and integration tests.
  * [Mocky](https://designer.mocky.io/) - A simple web app to generate custom HTTP responses for mocking HTTP requests. Also available as [open source](https://github.com/julien-lafont/Mocky).
  * [Mock N Roll](https://mocknroll.me/) - Free Mocks API Service—a powerful tool to simulate real API responses without backend delays. Perfect for frontend devs, QA testers, and DevOps teams. [repo](https://github.com/haerulmuttaqin/mocknroll-web).
  * [microenv.com](https://microenv.com) —  Create fake REST API for developers with the possibility to generate code and app in a docker container.
  * [Multi-Exit IP Address Checker](https://ip.alstra.ca/) —  A free and simple tool to check your exit IP address across multiple nodes and understand how your IP appears to different global regions and services. Useful for testing rule-based DNS splitting tools such as Control D.
  * [Namekit](https://namekit.app/) - AI-powered domain discovery – find available, standard-price names instantly. Free daily queries.
  * [News API](https://newsapi.org) — Search news on the web with code, and get JSON results. Developers get 100 queries free each day. Articles have a 24 hour delay.
  * [numlookupapi.com](https://numlookupapi.com) - Free phone number validation API - 100 free requests / month.
  * [OCR.Space](https://ocr.space/) — An OCR API parses image and pdf files that return the text results in JSON format. 25,000 requests per month are free and a 1MB file size limit.
  * [OpenAPI3 Designer](https://openapidesigner.com/) — Visually create Open API 3 definitions for free.
  * [parsehub.com](https://parsehub.com/) — Extract data from dynamic sites, turn dynamic websites into APIs, five projects free.
  * [Parseur](https://parseur.com) — 20 free pages/month: Extract data from PDFs, emails. AI powered. Full API access.
  * [PDFBolt](https://pdfbolt.com) - Developer-focused PDF generation API designed with privacy in mind. It offers Stripe-inspired documentation and includes 500 free PDF conversions per month.
  * [pdfEndpoint.com](https://pdfendpoint.com) - Effortlessly convert HTML or URLs to PDF with a simple API. One hundred conversions per month for free.
  * [PDF-API.io](https://pdf-api.io) - PDF Automation API, visual template editor or HTML to PDF, dynamic data integration, and PDF rendering with an API. The free plan comes with one template, 100 PDFs/month.
  * [Pixela](https://pixe.la/) - Free daystream database service. All operations are performed by API. Visualization with heat maps and line graphs is also possible.
  * [Postman](https://postman.com) — Simplify workflows and create better APIs – faster – with Postman, a collaboration platform for API development. Use the Postman App for free forever. Postman cloud features are also free forever with certain limits.
  * [Insomnia](https://insomnia.rest) - Open-source API client for designing and testing APIs, it supports REST and GraphQL
  * [PrefectCloud](https://www.prefect.io/cloud/) — A complete platform for dataflow automation. Free plan includes 5 deployed workflows and 500 minutes of serverless compute credits per month.
  * [Preset Cloud](https://preset.io/) - A hosted Apache Superset service. Forever free for teams of up to 5 users, featuring unlimited dashboards and charts, a no-code chart builder, and a collaborative SQL editor.
  * [PromptLoop](https://www.promptloop.com/) - PromptLoop delivers 10X easier AI web scraping with near-zero adoption time, 85%+ time saved on existing workflows, and operates 4X faster than manual research without compromise and includes a REST API endpoint for all research tasks. The first 1,000 credits are free each month.
  * [ProxySentry](https://proxysentry.io/) - IP API that detects residential proxies and VPNs. ProxySentry.io offers a free tier with 10k requests per month on rapidapi.com.
  * [Public-Apis Github Repo](https://github.com/public-apis/public-apis) — A list of free public APIs.
  * [Rapidapi](https://rapidapi.com/) - World’s Largest API Hub Millions of developers find and connect to thousands of APIs, API Development using fun challenges (with solutions!) and interactive examples.
  * [Rendi](https://rendi.dev) - FFmpeg API - A REST API for FFmpeg, run FFmpeg online without handling the infrastructure. Free tier with monthly processing quota and 4 vCPUs available.
  * [RequestBin.com](https://requestbin.com) — Create a free endpoint to which you can send HTTP requests. Any HTTP requests sent to that endpoint will be recorded with the associated payload and headers so you can observe recommendations from webhooks and other services.
  * [reqres.in](https://reqres.in) - A Free hosted REST-API ready to respond to your AJAX requests.
  * [Roboflow](https://roboflow.com) - create and deploy a custom computer vision model with no prior machine learning experience required. The free tier includes 30 credits per month.
  * [ROBOHASH](https://robohash.org/) - Web service to generate unique and cool images from any text.
  * [Scraper's Proxy](https://scrapersproxy.com) — Simple HTTP proxy API for scraping. Scrape anonymously without having to worry about restrictions, blocks, or captchas. First 100 successful scrapes per month free including javascript rendering (more available if you contact support).
  * [ScrapingAnt](https://scrapingant.com/) — Headless Chrome scraping API and free checked proxies service. Javascript rendering, premium rotating proxies, CAPTCHAs avoiding. Free 10,000 API credits.
  * [ScrapX](https://www.scrapx.io/) — Monitor for any visual or textual change in a target website and data extraction. Free plan allows upto 5 URLs a month.
  * [Simplescraper](https://simplescraper.io) — Trigger your webhook after each operation. The free plan includes 100 cloud scrape credits.
  * [Select Star](https://www.selectstar.com/) - is an intelligent data discovery platform that automatically analyzes and documents your data. Free light tier with 2 Data Source, up to 1,000 Tables and 25 Users.
  * [Sheetson](https://sheetson.com) - Instantly turn any Google Sheets into a RESTful API. Free plan available, including 1,000 free rows per sheet.
  * [Siterelic](https://siterelic.com/) - Siterelic API lets you take screenshots, audit websites, TLS scan, DNS lookup, test TTFB, and more. The free plan offers 100 API requests per month.
  * [SerpApi](https://serpapi.com/) - Real-time search engine scraping API. Returns structured JSON results for Google, YouTube, Bing, Baidu, Walmart, and many other machines. The free plan includes 100 successful API calls per month.
  * [SmartParse](https://smartparse.io) - SmartParse is a data migration and CSV to API platform that offers time- and cost-saving developer tools. The Free tier includes 300 Processing Units per month, Browser uploads, Data quarantining, Circuit breakers, and Job Alerts.
  * [Sofodata](https://www.sofodata.com/) - Create secure RESTful APIs from CSV files. Upload a CSV file and instantly access the data via its API allowing faster application development. The free plan includes 2 APIs and 2,500 API calls per month. You don't need a credit card.
  * [YourGPT CSV to JSON](https://yourgpt.ai/tools/csv-to-json) — A fast, free, and privacy-focused online tool to easily convert CSV files into structured JSON data right in your browser.
  * [Sqlable](https://sqlable.com/) - A collection of free online SQL tools, including an SQL formatter and validator, SQL regex tester, fake data generator, and interactive database playgrounds.
  * [Stoplight](https://stoplight.io/) - Saas for collaboratively designing and documenting for APIs. The free plan offers free design, mocking, and documentation tools.
  * [Supportivekoala](https://supportivekoala.com/) — Allows you to autogenerate images by your input via templates. The free plan allows you to create up to 50 images per month.
  * [Svix](https://www.svix.com/) - Webhooks as a Service. Send up to 50,000 messages/month for free.
  * [Tavily AI](https://tavily.com/) - API for online serach and rapid insights and comprehensive research, with the capability of organization of research results. 1000 request/month for the Free tier with No credit card required.
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
  * [DiffJSON](https://diffjson.com) - An online tool for comparing differences between two JSON data structures, helping you quickly locate the differences in JSON data.
  * [FreeIPAPI](https://freeipapi.com) - Free, Fast and Reliable IP Geolocation API for commercial and non-commercial users available in JSON

**[⬆️ Back to Top](#table-of-contents)**

## Artifact Repos

  * [Artifactory](https://jfrog.com/start-free/) - An artifact repository that supports numerous package formats like Maven, Docker, Cargo, Helm, PyPI, CocoaPods, and GitLFS. Includes package scanning tool XRay and CI/CD tool Pipelines (formerly Shippable) with a free tier of 2,000 CI/CD minutes per month.
  * [central.sonatype.org](https://central.sonatype.org) — The default artifact repository for Apache Maven, SBT, and other build systems.
  * [cloudrepo.io](https://cloudrepo.io) - Cloud-based, private and public, Maven and PyPi repositories. Free for open-source projects.
  * [cloudsmith.io](https://cloudsmith.io) — Simple, secure, and centralized repository service for Java/Maven, RedHat, Debian, Python, Ruby, Vagrant, and more. Free tier + free for open source.
  * [jitpack.io](https://jitpack.io/) — Maven repository for JVM and Android projects on GitHub, free for public projects.
  * [repsy.io](https://repsy.io) — 1 GB Free private/public Maven Repository.
  * [Gemfury](https://gemfury.com) — Private and public artifact repos for Maven, PyPi, NPM, Go Module, Nuget, APT, and RPM repositories. Free for public projects.
  * [paperspace](https://www.paperspace.com/) — Build & scale AI models, Develop, train, and deploy AI applications, free plan: public projects, 5Gb storage, basic instances.
  * [RepoForge](https://repoforge.io) - Private cloud-hosted repository for Python, Debian, NPM packages and Docker registries. Free plan for open source/public projects.
  * [RepoFlow](https://repoflow.io) - RepoFlow Simplifies package management with support for npm, PyPI, Docker, Go, Helm, and more. Try it for free with 10GB storage, 10GB bandwidth, 100 packages, and unlimited users in the cloud, or self-hosted for personal use only.

**[⬆️ Back to Top](#table-of-contents)**

## Tools for Teams and Collaboration
  * [3Cols](https://3cols.com/) - A free cloud-based code snippet manager for personal and collaborative code.
  * [Bitwarden](https://bitwarden.com) — The easiest and safest way for individuals, teams, and business organizations to store, share, and sync sensitive data.
  * [Braid](https://www.braidchat.com/) — Chat app designed for teams. Free for public access group, unlimited users, history, and integrations. also, it provides a self-hostable open-source version.
  * [cally.com](https://cally.com/) — Find the perfect time and date for a meeting. Simple to use, works great for small and large groups.
  * [Calendly](https://calendly.com) — Calendly is the tool for connecting and scheduling meetings. The free plan provides 1 Calendar connection per user and Unlimited sessions. Desktop and Mobile apps are also offered.
  * [Discord](https://discord.com/) — Chat with public/private rooms. Markdown text, voice, video, and screen sharing capabilities. Free for unlimited users.
  * [Fibo](https://fibo.dev) - A free online realtime scrum poker tool for agile teams that lets unlimited members estimate story points for faster planning.
  * [Telegram](https://telegram.org/) — Telegram is for everyone who wants fast, reliable messaging and calls. Business users and small teams may like the large groups, usernames, desktop apps, and powerful file-sharing options.
  * [DevToolLab](https://devtoollab.com) — Online developer tools offering free access to all basic tools, with the ability to auto save one entry per tool, standard processing speed, and community support.
  * [Dubble](https://dubble.so/) — Free Step-by-Step Guide creator. Take screenshots, document processes and colloborate with your team. Also supports async screen recording.
  * [Duckly](https://duckly.com/) — Talk and collaborate in real time with your team. Pair programming with IDE, terminal sharing, voice, video, and screen sharing. Free for small teams.
  * [Dyte](https://dyte.io) - The most developer-friendly live video & audio SDK, featuring collaborative plugins to enhance productivity and engagement. The free tier includes monthly 10,000 minutes of live video/audio usage.
  * [evernote.com](https://evernote.com/) — Tool for organizing information. Share your notes and work together with others
  * [Fibery](https://fibery.io/) — Connected workspace platform. Free for single users, up to 2 GB disk space.
  * [flock.com](https://flock.com) — A faster way for your team to communicate. Free Unlimited Messages, Channels, Users, Apps & Integrations
  * [Gather](https://www.gather.town/) - A better way to meet online. Centered around fully customizable spaces, Gather makes spending time with your communities just as easy as real life. Free for up to 10 concurrent users.
  * [gokanban.io](https://gokanban.io) - Syntax-based, no registration Kanban Board for fast use. Free with no limitations.
  * [flat.social](https://flat.social) - Interactive customizable spaces for team meetings & happy hours socials. Unlimited meetings, free up to 8 concurrent users.
  * [GitDailies](https://gitdailies.com) - Daily reports of your team's Commit and Pull Request activity on GitHub. Includes Push visualizer, peer recognition system, and custom alert builder. The free tier has unlimited users, three repos, and 3 alert configs.
  * [gitter.im](https://gitter.im/) — Chat, for GitHub. Unlimited public and private rooms, free for teams of up to 25
  * [Hackmd.io](https://hackmd.io/) - Real time collaboration & writing tool for markdown format docs/files. Like Google Docs but for markdown files. Free unlimited number of "notes", but the number of collaborators (invitee) for private notes & template [will be limited](https://hackmd.io/pricing).
  * [hangouts.google.com](https://hangouts.google.com/) — One place for all your conversations, for free, need a Google account
  * [HeySpace](https://hey.space) - Task management tool with chat, calendar, timeline and video calls. Free for up to 5 users.
  * [helplightning.com](https://www.helplightning.com/) — Help over video with augmented reality. Free without analytics, encryption, support
  * [ideascale.com](https://ideascale.com/) — Allow clients to submit ideas and vote, free for 25 members in 1 community
  * [Igloo](https://www.igloosoftware.com/) — Internal portal for sharing documents, blogs, calendars, etc. Free for up to 10 users.
  * [Keybase](https://keybase.io/) — Keybase is a FOSS alternative to Slack; it keeps everyone's chats and files safe, from families to communities to companies.
  * [Google Meet](https://meet.google.com/) — Use Google Meet for your business's online video meeting needs. Meet provides secure, easy-to-join online meetings.
  * [/meet for Slack](https://meetslack.com) - Start Google Meetings directly from Slack by using /meet in any channel, group, or DM. Free without any limitations.
  * [Linkinize](https://linkinize.com) — Bookmark manager for teams with tagging, multi-workspaces, and collaboration. Free plan includes 4 workspaces and 10 team members.
  * [Livecycle](https://www.livecycle.io/) — Livecycle is an inclusive collaboration platform that makes workflows frictionless for cross-functional product teams and open-source projects.
  * [Lockitbot](https://www.lockitbot.com/) — Reserve and lock shared resources within Slack like Rooms, Dev environments , servers etc. Free for upto 2 resources
  * [MarkUp](https://www.markup.io/) — MarkUp lets you collect feedback directly on top of your websites, PDFs and images.
  * [Proton Pass](https://proton.me/pass) — Password manager with built-in email aliases, 2FA authenticator, sharing and passkeys. Available on web, browser extension, and mobile app and desktop.
  * [Visual Debug](https://visualdebug.com) - A Visual feedback tool for better client-dev communication
  * [meet.jit.si](https://meet.jit.si/) — One-click video conversations, and screen sharing, for free
  * [Microsoft Teams](https://products.office.com/microsoft-teams/free) — Microsoft Teams is a chat-based digital hub that brings conversations, content, and apps together in one place all from a single experience. Free for up to 500k users.
  * [Miro](https://miro.com/) - Scalable, secure, cross-device, and enterprise-ready collaboration whiteboard for distributed teams. With a freemium plan.
  * [nootiz](https://www.nootiz.com/) - The go-to tool for gathering and managing visual feedback on any website
  * [Notion](https://www.notion.so/) - Notion is a note-taking and collaboration application with markdown support that integrates tasks, wikis, and databases. The company describes the app as an all-in-one workspace for note-taking, project management and task management. In addition to cross-platform apps, it can be accessed via most web browsers.
  * [Nuclino](https://www.nuclino.com) - A lightweight and collaborative wiki for all your team's knowledge, docs, and notes. Free plan with all essential features, up to 50 items, and 5GB storage.
  * [OnlineInterview.io](https://onlineinterview.io/) - Free code interview platform with embedded video chat, drawing board, and online code editor where you can compile and run your code on the browser. You can create a remote interview room with just one click.
  * [Quidlo Timesheets](https://www.quidlo.com/timesheets) - A simple timesheet and time tracking app for teams. The free plan has time tracking and generating reports features for up to 10 users.
  * [PageShare.dev](https://www.pageshare.dev) - Adds visual review capabilities into GitHub Pull Requests with no need to deploy websites. Free for up to 10 pages each month and 100MB of storage in total.
  * [Pendulums](https://pendulums.io/) - Pendulums is a free time tracking tool that helps you manage your time in a better manner with an easy-to-use interface and valuable statistics.
  * [Pumble](https://pumble.com) - Free team chat app. Unlimited users and message history, free forever.
  * [Raindrop.io](https://raindrop.io) - Private and secure bookmarking app for macOS, Windows, Android, iOS, and Web. Free Unlimited Bookmarks and Collaboration.
  * [element.io](https://element.io/) — A decentralized and open-source communication tool built on Matrix. Group chats, direct messaging, encrypted file transfers, voice and video chats, and easy integration with other services.
  * [Rocket.Chat](https://rocket.chat/) - Open-source communication platform with Omnichannel features, Matrix Federation, Bridge with others apps, Unlimited messaging, and Full messaging history.
  * [seafile.com](https://www.seafile.com/) — Private or cloud storage, file sharing, sync, discussions. The cloud version has just 1 GB
  * [Sema](https://www.semasoftware.com/) - Free developer portfolio tool able to consolidate and snapshot contributions across multiple repositories into a single report.
  * [Screen Sharing via Browser](https://screensharing.net) - Free screen sharing tool, share your screen with collabrators right from your browser, no download or registration needed. For free.
  * [Slab](https://slab.com/) — A modern knowledge management service for teams. Free for up to 10 users.
  * [slack.com](https://slack.com/) — Free for unlimited users with some feature limitations
  * [Spectrum](https://spectrum.chat/) - Create public or private communities for free.
  * [StatusPile](https://www.statuspile.com/) - A status page of status pages. Could you track the status pages of your upstream providers?
  * [Stickies](https://stickies.app/) - Visual collaboration app used for brainstorming, content curation, and notes. Free for up to 3 Walls, unlimited users, and 1 GB storage.
  * [Stacks](https://betterstacks.com/) - Content workspace with integrated notes, links, and file storage to navigate information overload. Forever free personal plan.
  * [StreamBackdrops](https://streambackdrops.com) — Free HD virtual backgrounds for video calls and team meetings. Professional backgrounds for Zoom, Teams, and Google Meet. No signup required, free for personal use.
  * [talky.io](https://talky.io/) — Free group video chat. Anonymous. Peer‑to‑peer. No plugins, signup, or payment required
  * [Teamhood](https://teamhood.com/) - Free Project, Task, and Issue-tracking software. Supports Kanban with Swimlanes and full Scrum implementation. Has integrated time tracking. Free for five users and three project portfolios.
  * [Teamplify](https://teamplify.com) - improve team development processes with Team Analytics and Smart Daily Standup. Includes full-featured Time Off management for remote-first teams. Free for small groups of up to 5 users.
  * [Tefter](https://tefter.io) - Bookmarking app with a powerful Slack integration. Free for open-source teams.
  * [TeleType](https://teletype.oorja.io/) — share terminals, voice, code, whiteboard, and more. no sign-in is required for end-to-end encrypted collaboration for developers.
  * [TimeCamp](https://www.timecamp.com/) - Free time tracking software for unlimited users. Easily integrates with PM tools like Jira, Trello, Asana, etc.
  * [Huly](https://huly.io/) - All-in-One Project Management Platform (alternative to Linear, Jira, Slack, Notion, Motion) - unlimited users, 10GB storage per workspace, 10GB video(audio) traffic.
  * [Teamcamp](https://www.teamcamp.app) - All-in-one project management application for software development companies.
  * [twist.com](https://twist.com) — An asynchronous-friendly team communication app where conversations stay organized and on-topic. Free and Unlimited plans are available. Discounts are provided for eligible teams.
  * [tldraw.com](https://tldraw.com) —  Free open-source white-boarding and diagramming tool with intelligent arrows, snapping, sticky notes, and SVG export features. Multiplayer mode for collaborative editing. Free official VS Code extension available as well.
  * [BookmarkOS.com](https://bookmarkos.com) - Free all-on-one bookmark manager, tab manager, and task manager in a customizable online desktop with folder collaboration.
  * [typetalk.com](https://www.typetalk.com/) — Share and discuss ideas with your team through instant messaging on the web or your mobile
  * [Tugboat](https://tugboat.qa) - Preview every pull request, automated and on-demand. Free for all, complimentary Nano tier for non-profits.
  * [whereby.com](https://whereby.com/) — One-click video conversations, for free (formerly known as appear.in)
  * [windmill.dev](https://windmill.dev/) - Windmill is an open-source developer platform to quickly build production-grade multi-step automation and internal apps from minimal Python and Typescript scripts. As a free user, you can create and be a member of at most three non-premium workspaces.
  * [vadoo.tv](https://vadoo.tv/) — Video hosting and marketing made simple. Upload videos with a single click. Record, manage, share & more. The free tier provides up to 10 videos, 1 GB of storage, and 10 GB of bandwidth/per month
  * [userforge.com](https://userforge.com/) - Interconnected online personas, user stories and context mapping.  Helps keep design and dev in sync free for up to 3 personas and two collaborators.
  * [wistia.com](https://wistia.com/) — Video hosting with viewer analytics, HD video delivery, and marketing tools to help understand your visitors, 25 videos, and Wistia branded player
  * [wormhol.org](https://www.wormhol.org/) — Straightforward file sharing service. Share unlimited files up to 5GB with as many peers as you want.
  * [Wormhole](https://wormhole.app/) - Share files up to 5GB with end-to-end encryption for up to 24hours. For files larger than 5 GB, it uses peer-to-peer transfer to send your files directly.
  * [zoom.us](https://zoom.us/) — Secure Video and Web conferencing add-ons available. The free plan is limited to 40 minutes.
  * [Zulip](https://zulip.com/) — Real-time chat with a unique email-like threading model. The free plan includes 10,000 messages of search history and File storage up to 5 GB. also, it provides a self-hostable open-source version.
  * [robocorp.com](https://robocorp.com) - Open-source stack for powering Automation Ops. Try out Cloud features and implement simple automation for free. Robot work 240 min/month, 10 Assistant runs, Storage of 100 MB.
  * [Fleep.io](https://fleep.io/) — Fleep an alternative to Slack. It has a free plan for small teams with full message history, unlimited 1:1 conversations, 1 group conversation, and 1 GB file storage.
  * [Chanty.com](https://chanty.com/) — Chanty is another alternative to Slack. It has a free forever plan for small teams (up to 10) with unlimited public and private conversations, searchable history, unlimited 1:1 audio calls, unlimited voice messages, ten integrations, and 20 GB storage per team.
  * [ruttl.com](https://ruttl.com/) — The best all-in-one feedback tool to collect digital feedback and review websites, PDFs, and images.
  * [Mattermost](https://mattermost.com/) — Secure collaboration for technical teams. Free plan with unlimited channels, playbooks, boards, users, 10GB storage, and more.
  * [Webvizio](https://webvizio.com) — Website feedback tool, website review software, and bug reporting tool for streamlining web development collaboration on tasks directly on live websites and web apps, images, PDFs, and design files.
  * [Pullflow](https://pullflow.com) — Pullflow offers an AI-enhanced platform for code review collaboration across GitHub, Slack, and VS Code.
  * [Webex](https://www.webex.com/) — Video meetings with a free plan offering 40 minutes per meeting with 100 attendees.
  * [RingCentral](https://www.ringcentral.com/) — Video meetings with a free plan offering 50 minutes per meeting with 100 participants.
  * [GitBook](https://www.gitbook.com/) — Platform for capturing and documenting technical knowledge — from product docs to internal knowledge bases and APIs. Free plan for individual developers.
  * [transfernow](https://www.transfernow.net/) — simplest, fastest and safest interface to transfer and share files. Send photos, videos and other large files without a manditory subscription.
  * [paste.sh](https://paste.sh/) — This is a JavaScript and the Crypto based simple paste site.
  * [Revolt.chat](https://revolt.chat/) — An OpenSource alternative for[Discord](https://discord.com/), that respects your privacy. It also have most proprietary features from discord for free. Revolt is a all in one application that is secure and fast, while being 100% free. every features are free. They also have (official & unofficial) plugins support unlike most main-stream chatting applications.
  * [Tencent RTC](https://trtc.io/) — Tencent Real-Time Communication (TRTC) offers solutions for group audio/video calls.10,000 free minutes/month for the first year.
  * [Pastefy](https://pastefy.app/) - Beautiful and simple Pastebin with optional Client-Encryption, Multitab-Pastes, an API, a highlighted Editor and more.
  * [SiteDots](https://sitedots.com/) - Share feedback for website projects directly on your website, no emulation, canvas or workarounds. Completely functional free tier.

  * [Cushion](https://cushion.so/) - Async-friendly alternative to Slack. built for small, distributed teams who are productive. Free tier with 30 posts, 5 members and unlimited guests.

**[⬆️ Back to Top](#table-of-contents)**

## CMS

  * [acquia.com](https://www.acquia.com/) — Hosting for Drupal sites. Free tier for developers. Free development tools (such as Acquia Dev Desktop) are also available.
  * [Contentful](https://www.contentful.com/) — Headless CMS. Content management and delivery APIs in the cloud. Comes with one free Community space that includes five users, 25K records, 48 Content Types, 2 locales.
  * [Cosmic](https://www.cosmicjs.com/) — Headless CMS and API toolkit. Free personal plans for developers.
  * [Crystallize](https://crystallize.com) — Headless PIM with ecommerce support. Built-in GraphQL API. The free version includes unlimited users, 1000 catalog items, 5 GB/month bandwidth, and 25k/month API calls.
  * [DatoCMS](https://www.datocms.com/) - Offers free tier for small projects. DatoCMS is a GraphQL-based CMS. On the lower tier, you have 100k/month calls.
  * [Directus](https://directus.io) — Headless CMS. A completely free and open-source platform for managing assets and database content on-prem or in the Cloud. There are no limitations or paywalls.
  * [FrontAid](https://frontaid.io/) — Headless CMS that stores JSON content directly in your Git repository. No restrictions.
  * [kontent.ai](https://www.kontent.ai) - A Content-as-a-Service platform that gives you all the headless CMS benefits while empowering marketers at the same time. The developer plan provides two users with unlimited projects with two environments for each, 500 content items, two languages with Delivery and Management API, and Custom elements support. You can use more detailed plans to meet your needs.
  * [Prismic](https://www.prismic.io/) — Headless CMS. Content management interface with fully hosted and scalable API. The Community Plan provides unlimited API calls, documents, custom types, assets, and locales to one user. Everything that you need for your next project. Bigger free plans are available for Open Content/Open Source projects.
  * [Sanity.io](https://www.sanity.io/) - Platform for structured content with an open-source editing environment and a real-time hosted data store. Unlimited projects. Unlimited admin users, three non-admin users, two datasets, 500K API CDN requests, 10GB bandwidth, and 5GB assets included for free per project.
  * [sensenet](https://sensenet.com) - API-first headless CMS providing enterprise-grade solutions for businesses of all sizes. The Developer plan provides three users, 500 content items, three built-in roles, 25+5 content types, fully accessible REST API, document preview generation, and Office Online editing.
  * [TinaCMS](https://tina.io/) — Replacing Forestry.io. Open source Git-backed headless CMS that supports Markdown, MDX, and JSON. The basic offer is free with two users available.
  * [GatsbyjsCMS](https://www.gatsbyjs.com/) - Gatsby is the fast and flexible framework that makes building websites with any CMS, API, or database fun again. Build and deploy headless websites that drive more traffic, convert better, and earn more revenue!
  * [Hygraph](https://hygraph.com/) - Offers free tier for small projects. GraphQL first API. Move away from legacy solutions to the GraphQL native Headless CMS - and deliver omnichannel content API first.
  * [Squidex](https://squidex.io/) - Offers free tier for small projects. API / GraphQL first. Open source and based on event sourcing (versing every change automatically).
  * [InstaWP](https://instawp.com/) - Launch a WordPress site in a few seconds. A free tier with 5 Active Sites, 500 MB Space, 48 hrs Site Expiry.
  * [Storyblok](https://www.storyblok.com) - A Headless CMS for developers and marketers that works with all modern frameworks. The Community (free) tier offers Management API, Visual Editor, ten sources, Custom Field Types, Internationalization (unlimited languages/locales), Asset Manager (up to 2500 assets), Image Optimizing Service, Search Query, Webhook + 250GB Traffic/month included.
  * [WPJack](https://wpjack.com) - Set up WordPress on any cloud in less than 5 minutes! The free tier includes 1 server, 2 sites, free SSL certificates, and unlimited cron jobs. No time limits or expirations—your website, your way.
  * [Solo](https://soloist.ai) - Free AI website creator from Mozilla, create a beautiful website for your business from a few simple inputs. Free custom domain, no credit card needed.

**[⬆️ Back to Top](#table-of-contents)**

## Code Generation

  * [Appinvento](https://appinvento.io/) — AppInvento is a free No code app builder. In the automatically generated backend code, users have complete access to the source code and unlimited APIs and routes, allowing for extensive integration. The free plan includes three projects, five tables, and a Google add-on.
  * [Cody AI](https://sourcegraph.com/cody) - Cody is a coding AI assistant that uses AI and a deep understanding of your codebase to help you write and understand code faster. Cody gives developers a choice of LLMs (including local inference), has support for various IDEs, supports all popular programming languages, and has a free plan. The free plan gives developers 20 chat messages (using Claude 3 Sonnet as the LLM) and 500 autocompletions (using the Starcoder 16b) each month.
  * [DhiWise](https://www.dhiwise.com/) — Seamlessly turn Figma designs into dynamic Flutter & React applications with DhiWise's innovative code generation technology, optimizing your workflow and helping you craft exceptional mobile and web experiences faster than ever before.
  * [Metalama](https://www.postsharp.net/metalama) - Only for C#. Metalama generates the boilerplate of the code on the fly during compilation so that your source code remains clean. It is free for open-source projects, and its commercial-friendly free tier includes three aspects.
  * [Supermaven](https://www.supermaven.com/) — Supermaven is a fast AI code completion plugin for VSCode, JetBrains, and Neovim. Free tier provides unlimited inline completions.
  * [tabnine.com](https://www.tabnine.com/) — Tabnine helps developers create better software faster by providing insights learned from all the code in the world. Plugin available.
  * [v0.dev](https://v0.dev/) — v0 uses AI models to generate code based on simple text prompts. It generates copy-and-paste friendly React code based on shadcn/ui and Tailwind CSS that people can use in their projects. Each generation takes at minimum 30 credits. You start up with 1200 credits, and get 200 free credits every month.


**[⬆️ Back to Top](#table-of-contents)**

## Code Quality

  * [beanstalkapp.com](https://beanstalkapp.com/) — A complete workflow to write, review, and deploy code), a free account for one user, and one repository with 100 MB of storage
  * [browserling.com](https://www.browserling.com/) — Live interactive cross-browser testing, free only 3 minutes sessions with MS IE 9 under Vista at 1024 x 768 resolution
  * [codacy.com](https://www.codacy.com/) — Automated code reviews for PHP, Python, Ruby, Java, JavaScript, Scala, CSS, and CoffeeScript, free for unlimited public and private repositories
  * [Codeac.io](https://www.codeac.io/infrastructure-as-code.html?ref=free-for-dev) - Automated Infrastructure as Code review tool for DevOps integrates with GitHub, Bitbucket, and GitLab (even self-hosted). In addition to standard languages, it also analyzes Ansible, Terraform, CloudFormation, Kubernetes, and more. (open-source free)
  * [codeclimate.com](https://codeclimate.com/) — Automated code review, free for Open Source and unlimited organisation-owned private repos (up to 4 collaborators). Also free for students and institutions.
  * [codecov.io](https://codecov.io/) — Code coverage tool (SaaS), free for Open Source and one free private repo
  * [CodeFactor](https://www.codefactor.io) — Automated Code Review for Git. The free version includes unlimited users, public repositories, and one private repo.
  * [coderabbit.ai](https://coderabbit.ai) — AI-powered code review tool that integrates with GitHub/GitLab. Free tier includes 200 files/hour, 3 reviews per hour, and 50 conversations/hour. Free forever for open source projects.
  * [codescene.io](https://codescene.io/) - CodeScene prioritizes technical debt based on how the developers work with the code and visualizes organizational factors like team coupling and system mastery. Free for Open Source.
  * [CodSpeed](https://codspeed.io) - Automate performance tracking in your CI pipelines. Catch performance regressions before deployment, thanks to precise and consistent metrics. Free forever for Open Source projects.
  * [coveralls.io](https://coveralls.io/) — Display test coverage reports, free for Open Source
  * [dareboost](https://dareboost.com) - 5 free analysis reports for web performance, accessibility, and security each month
  * [deepcode.ai](https://www.deepcode.ai) — DeepCode finds bugs, security vulnerabilities, performance and API issues based on AI. DeepCode's speed of analysis allows us to analyze your code in real time and deliver results when you hit the save button in your IDE. Supported languages are Java, C/C++, JavaScript, Python, and TypeScript. Integrations with GitHub, BitBucket, and GitLab. Free for open source and private repos and up to 30 developers.
  * [deepscan.io](https://deepscan.io) — Advanced static analysis for automatically finding runtime errors in JavaScript code, free for Open Source
  * [DeepSource](https://deepsource.io/) - DeepSource continuously analyzes source code changes, finding and fixing issues categorized under security, performance, anti-patterns, bug-risks, documentation, and style. Native integration with GitHub, GitLab, and Bitbucket.
  * [DiffText](https://difftext.com) - Instantly find the differences between two blocks of code. Completely free to use.
  * [eversql.com](https://www.eversql.com/) — EverSQL - The #1 platform for database optimization. Gain critical insights into your database and SQL queries automatically.
  * [gerrithub.io](https://review.gerrithub.io/) — Gerrit code review for GitHub repositories for free
  * [gocover.io](https://gocover.io/) — Code coverage for any [Go](https://golang.org/) package
  * [goreportcard.com](https://goreportcard.com/) — Code Quality for Go projects, free for Open Source
  * [gtmetrix.com](https://gtmetrix.com/) — Reports and thorough recommendations to optimize websites
  * [holistic.dev](https://holistic.dev/) - The #1 static code analyzer for Postgresql optimization. Performance, security, and architect database issues automatic detection service
  * [houndci.com](https://houndci.com/) — Comments on GitHub commits about code quality, free for Open Source
  * [Moderne.io](https://app.moderne.io) — Automatic source code refactoring. Moderne offers framework migrations, code analysis with remediation, and unrivaled code transformation at scale, so developers can spend their time building new things instead of maintaining the old. Free for Open Source.
  * [reviewable.io](https://reviewable.io/) — Code review for GitHub repositories, free for public or personal repos.
  * [parsers.dev](https://parsers.dev/) - Abstract syntax tree parsers and intermediate representation compilers as a service
  * [scan.coverity.com](https://scan.coverity.com/) — Static code analysis for Java, C/C++, C# and JavaScript, free for Open Source
  * [scrutinizer-ci.com](https://scrutinizer-ci.com/) — Continuous inspection platform, free for Open Source
  * [semanticdiff.com](https://app.semanticdiff.com/) — Programming language aware diff for GitHub pull requests and commits, free for public repositories
  * [shields.io](https://shields.io) — Quality metadata badges for open source projects
  * [sonarcloud.io](https://sonarcloud.io) — Automated source code analysis for Java, JavaScript, C/C++, C#, VB.NET, PHP, Objective-C, Swift, Python, Groovy and even more languages, free for Open Source
  * [SourceLevel](https://sourcelevel.io/) — Automated Code Review and Team Analytics. Free for Open Source and organizations up to 5 collaborators.
  * [webceo.com](https://www.webceo.com/) — SEO tools but with also code verifications and different types of devices
  * [zoompf.com](https://zoompf.com/) — Fix the performance of your web sites, detailed analysis

**[⬆️ Back to Top](#table-of-contents)**

## Code Search and Browsing

  * [libraries.io](https://libraries.io/) — Search and dependency update notifications for 32 different package managers, free for open source
  * [Namae](https://namae.dev/) - Search various websites like GitHub, Gitlab, Heroku, Netlify, and many more for the availability of your project name.
  * [searchcode.com](https://searchcode.com/) — Comprehensive text-based code search, free for Open Source
  * [tickgit.com](https://www.tickgit.com/) — Surfaces `TODO` comments (and other markers) to identify areas of code worth returning to for improvement.
  * [CodeKeep](https://codekeep.io) - Google Keep for Code Snippets. Organize, Discover, and share code snippets, featuring a powerful code screenshot tool with preset templates and a linking feature.

**[⬆️ Back to Top](#table-of-contents)**

## CI and CD

  * [AccessLint](https://github.com/marketplace/accesslint) — AccessLint brings automated web accessibility testing into your development workflow. It's free for open source and education purposes.
  * [appcircle.io](https://appcircle.io) — An enterprise-grade mobile DevOps platform that automates the build, test, and publish store of mobile apps for faster, efficient release cycle. Free for 30 minutes max build time per build, 20 monthly builds and 1 concurrent build.
  * [appveyor.com](https://www.appveyor.com/) — CD service for Windows, free for Open Source
  * [LocalOps](https://localops.co/) - Deploy your app on AWS/GCP/Azure in under 30 minutes. Setup standardised app environments on any cloud, which come with in-built continuous deployment automation and advanced observability. The free plan allows 1 user and 1 app environment.
  * [Argonaut](https://argonaut.dev/) - Deploy apps and infrastructure on your cloud in minutes. Support for custom and third-party app deployments on Kubernetes and Lambda environments. The free tier allows unlimited apps and deployments for 5 domains and 2 users.
  * [bitrise.io](https://www.bitrise.io/) — A CI/CD for mobile apps, native or hybrid. With 200 free builds/month 10 min build time and two team members. OSS projects get 45 min build time, +1 concurrency and unlimited team size.
  * [buddy.works](https://buddy.works/) — A CI/CD with five free projects and one concurrent run (120 executions/month)
  * [Buildkite](https://buildkite.com) CI Pipelines free for 3 users and 5k job minutes/month. Test Analytics free developer tier includes 100k test executions/month, with more free inclusions for open-source projects.
  * [bytebase.com](https://www.bytebase.com/) — Database CI/CD and DevOps. Free under 20 users and ten database instances
  * [CircleCI](https://circleci.com/) — Comprehensive free plan with all features included in a hosted CI/CD service for GitHub, GitLab, and BitBucket repositories. Multiple resource classes, Docker, Windows, Mac OS, ARM executors, local runners, test splitting, Docker Layer Caching, and other advanced CI/CD features. Free for up to 6000 minutes/month execution time, unlimited collaborators, 30 parallel jobs in private projects, and up to 80,000 free build minutes for Open Source projects.
  * [cirrus-ci.org](https://cirrus-ci.org) - Free for public GitHub repositories
  * [cirun.io](https://cirun.io) - Free for public GitHub repositories
  * [codefresh.io](https://codefresh.io) — Free-for-Life plan: 1 build, one environment, shared servers, unlimited public repos
  * [codemagic.io](https://codemagic.io/) - Free 500 build minutes/month
  * [codeship.com](https://codeship.com/) — 100 private builds/month, five private projects, unlimited for Open Source
  * [deploybot.com](https://www.deploybot.com/) — 1 repository with ten deployments, free for Open Source
  * [deployhq.com](https://www.deployhq.com/) — 1 project with ten daily deployments (30 build minutes/month)
  * [drone](https://cloud.drone.io/) - Drone Cloud enables developers to run Continuous Delivery pipelines across multiple architectures - including x86 and Arm (both 32-bit and 64-bit) - all in one place
  * [LayerCI](https://layerci.com) — CI for full stack projects. One full stack preview environment with 5GB memory & 3 CPUs.
  * [semaphoreci.com](https://semaphoreci.com/) — Free for Open Source, 100 private builds per month
  * [Squash Labs](https://www.squash.io/) — creates a VM for each branch and makes your app available from a unique URL, Unlimited public & private repos, Up to 2 GB VM Sizes.
  * [styleci.io](https://styleci.io/) — Public GitHub repositories only
  * [Mergify](https://mergify.com) — workflow automation and merge queue for GitHub — Free for public GitHub repositories
  * [Make](https://www.make.com/en) — The workflow automation tool lets you connect apps and automate workflows using UI. It supports many apps and the most popular APIs. Free for public GitHub repositories, and free tier with 100 Mb, 1000 Operations, and 15 minutes of minimum interval.
  * [Shipfox](https://www.shipfox.io/) - Run your GitHub actions 2x faster, 3.000 build minutes free each month.
  * [Spacelift](https://spacelift.io/) - Management platform for Infrastructure as Code. Free plan features: IaC collaboration, Terraform module registry, ChatOps integration, Continuous resource compliance with Open Policy Agent, SSO with SAML 2.0, and access to public worker pools: up to 200 minutes/month
  * [microtica.com](https://microtica.com/) - Startup environments with ready-made infrastructure components, deploy apps on AWS for free, and support your production workloads. The free tier includes 1 Environment (on your AWS account), 2 Kubernetes Services, 100 build minutes per month, and 20 monthly deployments.
  * [Nx Cloud](https://nx.dev/ci) - Nx Cloud speeds up your monorepos on CI with features such as remote caching, distribution of tasks across machines and even automated splitting of your e2e test runs. It comes with a free plan for up to 30 contributors with generous 150k credits included.
  * [blacksmith](https://www.blacksmith.sh/) - Managed performance runners for GitHub Actions that provides 3,000 free minutes per month, with no credit card needed.
  * [Terramate](https://terramate.io/) - Terramate is an orchestration and management platform for Infrastructure as Code (IaC) tools such as Terraform, OpenTofu, and Terragrunt. Free up to 2 users including all features.
  * [Terrateam](https://terrateam.io) - GitOps-first Terraform automation with pull request-driven workflows, project isolation via self-hosted runners, and layered runs for ordered operations. Free for up to 3 users.

**[⬆️ Back to Top](#table-of-contents)**

## Testing

  * [Applitools.com](https://applitools.com/) — Smart visual validation for web, native mobile and desktop apps. Integrates with almost all automation solutions (like Selenium and Karma) and remote runners (Sauce Labs, Browser Stack). free for open source. A free tier for a single user with limited checkpoints per week.
  * [Appetize](https://appetize.io) — Test your Android & iOS apps on this Cloud Based Android Phone / Tablets emulator and iPhone/iPad simulators directly in your browser. The free tier includes two concurrent session with 30 minutes of usage per month. No limit on app size.
  * [Apptim](https://apptim.com) — A mobile testing tool that enables people without performance engineering skills to evaluate an app's performance and user experience (UX). A desktop version using your own device is 100% FREE, with unlimited tests on both iOS and Android.
  * [Argos](https://argos-ci.com) - Open Source visual testing for developers. Unlimitedprojects, with 5,000 screenshots per month. Free for open-source projects.
  * [Bencher](https://bencher.dev/) - A continuous benchmarking tool suite to catch CI performance regressions. Free for all public projects.
  * [browserstack.com](https://www.browserstack.com/) — Manual and automated browser testing, [free for Open Source](https://www.browserstack.com/open-source?ref=pricing)
  * [BugBug](https://bugbug.io/) - Lightweight test automation tool for web applications. It is easy to learn and doesn't require coding. You can run unlimited tests on your own computer for free. You also get cloud monitoring and CI/CD integration for an additional monthly fee.
  * [Checkly](https://checklyhq.com) - Code-first synthetic monitoring for modern DevOps. Monitor your APIs and apps at a fraction of the price of legacy providers. Powered by a Monitoring as Code workflow and Playwright. Generous free tier for devs.
  * [checkbot.io](https://www.checkbot.io/) — Browser extension that tests if your website follows 50+ SEO, speed and security best practices. Free tier for smaller websites.
  * [CORS-Tester](https://cors-error.dev/cors-tester/) - A free tool for developers and API testers to check if an API is CORS-enabled for a given domain and identify gaps. Get actionable insights.
  * [cypress.io](https://www.cypress.io/) - Fast, easy and reliable testing for anything that runs in a browser. Cypress Test Runner is always free and open-source with no restrictions and limitations. Cypress Dashboard is free for open-source projects for up to 5 users.
  * [Cypress Recorder by Preflight](https://cypress.preflight.com/) - Create AI-powered Cypress Tests/POM models on your browser. It's open-source, except for the AI part. It's free for five monthly test creations with Self-healing scripts, Email, and Visual testing.
  * [everystep-automation.com](https://www.everystep-automation.com/) — Records and replays all steps made in a web browser and creates scripts, free with fewer options
  * [Gremlin](https://www.gremlin.com/gremlin-free-software) — Gremlin's Chaos Engineering tools allow you to safely and securely inject failure into your systems to find weaknesses before they cause customer-facing issues. Gremlin Free provides access to Shutdown and CPU attacks on up to 5 hosts or containers.
  * [gridlastic.com](https://www.gridlastic.com/) — Selenium Grid testing with a free plan of up to 4 simultaneous selenium nodes/10 grid starts/4,000 test minutes/month
  * [katalon.com](https://katalon.com) - Provides a testing platform that can help teams of all sizes at different levels of testing maturity, including  Katalon Studio, TestOps (+ Visual Testing free), TestCloud, and Katalon Recorder.
  * [Keploy](https://keploy.io/) - Keploy is a functional testing toolkit for developers. Recording API calls generates E2E tests for APIs (KTests) and mocks or stubs(KMocks). It is free for Open Source projects.
  * [knapsackpro.com](https://knapsackpro.com) - Speed up your tests with optimal test suite parallelization on any CI provider. Split Ruby, JavaScript tests on parallel CI nodes to save time. Free plan for up to 10 minutes of test files and free unlimited plan for Open Source projects.
  * [lambdatest.com](https://www.lambdatest.com/) — Manual, visual, screenshot, and automated browser testing on selenium and cypress, [free for Open Source](https://www.lambdatest.com/open-source-cross-browser-testing-tool)
  * [loadmill.com](https://www.loadmill.com/) - Automatically create API and load tests by analyzing network traffic. Simulate up to 50 concurrent users for up to 60 minutes for free monthly.
  * [lost-pixel.com](https://lost-pixel.com) - holistic visual regression testing for your Storybook, Ladle, Histoire stories and Web Apps. Unlimited team members, totally free for open-source, 7,000 snapshots/month.
  * [octomind.dev](https://www.octomind.dev/) - Auto-generated, run and maintained Playwright UI tests with AI-assisted test case generation
  * [pagegym.com](https://pagegym.com) - Load behvariour and page speed analysis and optimization tool. The free plan provides 10 tests per day, 5 experiments per week, and 15 GB of maximum ingested data per month.
  * [percy.io](https://percy.io) - Add visual testing to any web app, static site, style guide, or component library.  Unlimited team members, Demo app, and unlimited projects, 5,000 snapshots/month.
  * [qase.io](https://qase.io) - Test management system for Dev and QA teams. Manage test cases, compose test runs, perform tests, track defects, and measure impact. The free tier includes all core features, with 500MB available for attachments and up to 3 users.
  * [Repeato](https://repeato.app/) No-code mobile app test automation tool built on top of computer vision and AI. Works for native apps, flutter, react-native, web, ionic, and many more app frameworks. The free plan is limited to 10 tests for iOS and 10 for Android, but includes most of the features of the paid plans, including unlimited test runs.
  * [Requestly](https://requestly.com/) Open-source Chrome Extension to Intercept, Redirect and Mock HTTP Requests. Featuring [Debugger](https://requestly.com/products/web-debugger/), [Mock Server](https://requestly.com/products/mock-server/), [API Client](https://requestly.com/products/api-client/) and [Session Recording](https://requestly.com/products/session-book/).  Redirect URLs, Modify HTTP Headers, Mock APIs, Inject custom JS, Modify GraphQL Requests, Generate Mock API Endpoints, Record session with Network & Console Logs. Create upto 10 rules in Free Tier. Free for open-source.
  * [seotest.me](https://seotest.me/) — Free on-page SEO website tester. 10 free website crawls per day. Useful SEO learning resources and recommendations on how to improve the on-page SEO results for any website regardless of technology.
  * [snippets.uilicious.com](https://snippets.uilicious.com) - It's like CodePen but for cross-browser testing. UI-licious lets you write tests like user stories and offers a free platform - UI-licious Snippets - that allows you to run unlimited tests on Chrome with no sign-up required for up to 3 minutes per test run. Found a bug? You can copy the unique URL to your test to show your devs exactly how to reproduce the bug.
  * [SSR (Server-side Rendering) Checker](https://www.crawlably.com/ssr-checker/) - Check SSR (server-side rendering) for any URL by visually comparing the server rendered version of the page with the regular version.
  * [TestCollab](https://testcollab.com) - A user-friendly test management software, its free plan includes Jira integration, unlimited projects, test case import using CSV/XLSx, time tracking, and 1 GB file storage.
  * [testingbot.com](https://testingbot.com/) — Selenium Browser and Device Testing, [free for Open Source](https://testingbot.com/open-source)
  * [Testspace.com](https://testspace.com/) - A Dashboard for publishing automated test results and a Framework for implementing manual tests as code using GitHub. The service is [free for Open Source](https://github.com/marketplace/testspace-com) and accounts for 450 monthly results.
  * [tesults.com](https://www.tesults.com) — Test results reporting and test case management. Integrates with popular test frameworks. Open Source software developers, individuals, educators, and small teams getting started can request discounted and free offerings beyond basic free projects.
  * [UseWebhook.com](https://usewebhook.com) - Capture and inspect webhooks from your browser. Forward to localhost, or replay from history. Free to use.
  * [Vaadin](https://vaadin.com) — Build scalable UIs in Java or TypeScript, and use the integrated tooling, components, and design system to iterate faster, design better, and simplify the development process. Unlimited Projects with five years of free maintenance.
  * [websitepulse.com](https://www.websitepulse.com/tools/) — Various free network and server tools.
  * [webhook-test.com](https://webhook-test.com) - Debug and inspect webhooks and HTTP requests with a unique URL during integration. Completely free, you can create unlimited URLs and receive recommendations.
  * [webhook.site](https://webhook.site) - Verify webhooks, outbound HTTP requests, or emails with a custom URL. A temporary URL and email address are always free.
  * [webhookbeam.com](https://webhookbeam.com) - Set up webhooks and monitor them via push notifications and emails.
 

**[⬆️ Back to Top](#table-of-contents)**

## Security and PKI

  * [aikido.dev](https://www.aikido.dev) — All-in-one appsec platform covering SCA, SAST, CSPM, DAST, Secrets, IaC, Malware, Container scanning, EOL,... Free plan includes two users, scanning of 10 repos, 1 cloud, 2 containers & 1 domain.
  * [alienvault.com](https://www.alienvault.com/open-threat-exchange/reputation-monitor) — Uncovers compromised systems in your network
  * [Altcha.org](https://altcha.org/anti-spam) - A Spam Filter for websites and APIs powered by natural language processing and machine learning. Free plan includes 200 requests a day per domain.
  * [atomist.com](https://atomist.com/) — A quicker and more convenient way to automate various development tasks. Now in beta.
  * [cloudsploit.com](https://cloudsploit.com/) — Amazon Web Services (AWS) security and compliance auditing and monitoring
  * [Public Cloud Threat Intelligence](https://cloudintel.himanshuanand.com/) — High confidence Indicator of Compromise(IOC) targeting public cloud infrastructure, A portion is available on github (https://github.com/unknownhad/AWSAttacks). Full list is available via API
  * [CodeNotary.io](https://www.codenotary.io/) — Open Source platform with indelible proof to notarize code, files, directories, or container
  * [crypteron.com](https://www.crypteron.com/) — Cloud-first, developer-friendly security platform prevents data breaches in .NET and Java applications
  * [CyberChef](https://gchq.github.io/CyberChef/) — A simple, intuitive web app for analyzing and decoding/encoding data without dealing with complex tools or programming languages. Like a Swiss army knife of cryptography & encryption. All features are free to use, with no limit. Open source if you wish to self-host.
  * [DAS](https://signup.styra.com/) — Styra DAS Free, Full lifecycle policy management to create, deploy and manage Open Policy Agent(OPA) authorization
  * [Datree](https://www.datree.io/) — Open Source CLI tool to prevent Kubernetes misconfigurations by ensuring that manifests and Helm charts follow best practices as well as your organization’s policies
  * [Dependabot](https://dependabot.com/) Automated dependency updates for Ruby, JavaScript, Python, PHP, Elixir, Rust, Java (Maven and Gradle), .NET, Go, Elm, Docker, Terraform, Git Submodules, and GitHub Actions.
  * [DJ Checkup](https://djcheckup.com) — Scan your Django site for security flaws with this free, automated checkup tool. Forked from the Pony Checkup site.
  * [Doppler](https://doppler.com/) — Universal Secrets Manager for application secrets and config, with support for syncing to various cloud providers. Free for five users with basic access controls.
  * [Dotenv](https://dotenv.org/) — Sync your .env files, quickly & securely. Stop sharing your .env files over insecure channels like Slack and email, and never lose an important .env file again. Free for up to 3 teammates.
  * [GitGuardian](https://www.gitguardian.com) — Keep secrets out of your source code with automated secrets detection and remediation. Scan your git repos for 350+ types of secrets and sensitive files – Free for individuals and teams of 25 developers or less.
  * [Have I been pwned?](https://haveibeenpwned.com) — REST API for fetching the information on the breaches.
  * [hostedscan.com](https://hostedscan.com) — Online vulnerability scanner for web applications, servers, and networks. Ten free scans per month.
  * [Infisical](https://infisical.com/) — Open source platform that lets you manage developer secrets across your team and infrastructure: everywhere from local development to staging/production 3rd-party services. Free for up to 5 developers.
  * [Internet.nl](https://internet.nl) — Test for modern Internet Standards like IPv6, DNSSEC, HTTPS, DMARC, STARTTLS and DANE
  * [keychest.net](https://keychest.net) - SSL expiry management and cert purchase with an integrated CT database
  * [letsencrypt.org](https://letsencrypt.org/) — Free SSL Certificate Authority with certs trusted by all major browsers
  * [meterian.io](https://www.meterian.io/) - Monitor Java, Javascript, .NET, Scala, Ruby, and NodeJS projects for security vulnerabilities in dependencies. Free for one private project, unlimited projects for open source.
  * [Mozilla Observatory](https://observatory.mozilla.org/) — Find and fix security vulnerabilities in your site.
  * [opswat.com](https://www.opswat.com/) — Security Monitoring of computers, devices, applications, configurations, Free 25 users and 30 days history users.
  * [openapi.security](https://openapi.security/) - Free tool to quickly check the security of any OpenAPI / Swagger-based API. You don't need to sign up.
  * [pixee.ai](https://pixee.ai) - Automated Product Security Engineer as a free GitHub bot that submits PRs to your Java code base to automatically resolve vulnerabilities. Other languages coming soon!
  * [pyup.io](https://pyup.io) — Monitor Python dependencies for security vulnerabilities and update them automatically. Free for one private project, unlimited projects for open source.
  * [qualys.com](https://www.qualys.com/community-edition) — Find web app vulnerabilities, audit for OWASP Risks
  * [report-uri.io](https://report-uri.io/) — CSP and HPKP violation reporting
  * [seclookup.com](https://www.seclookup.com/) - Seclookup APIs can enrich domain threat indicators in SIEM, provide comprehensive information on domain names, and improve threat detection & response. Get 50K lookups free [here](https://account.seclookup.com/).
  * [snyk.io](https://snyk.io) — Can find and fix known security vulnerabilities in your open-source dependencies. Unlimited tests and remediation for open-source projects. Limited to 200 tests/month for your private projects.
  * [Socket](https://socket.dev) — Free supply chain security for individual developers, small teams, and open source projects. Includes a free app and firewall CLI tool to protect your code from vulnerable and malicious dependencies. Detects 70+ indicators of supply chain risk.
  * [ssllabs.com](https://www.ssllabs.com/ssltest/) — Intense analysis of the configuration of any SSL web server
  * [SOOS](https://soos.io) - Free, unlimited SCA scans for open-source projects. Detect and fix security threats before release. Protect your projects with a simple and effective solution.
  * [StackHawk](https://www.stackhawk.com/) Automate application scanning throughout your pipeline to find and fix security bugs before they hit production. Unlimited scans and environments for a single app.
  * [Sucuri SiteCheck](https://sitecheck.sucuri.net) - Free website security check and malware scanner
  * [Protectumus](https://protectumus.com) - Free website security check, site antivirus, and server firewall (WAF) for PHP. Email notifications for registered users in the free tier.
  * [TestTLS.com](https://testtls.com) - Test an SSL/TLS service for secure server configuration, certificates, chains, etc. Not limited to HTTPS.
  * [threatconnect.com](https://threatconnect.com) — Threat intelligence: It is designed for individual researchers, analysts, and organizations starting to learn about cyber threat intelligence. Free up to 3 Users
  * [tinfoilsecurity.com](https://www.tinfoilsecurity.com/) — Automated vulnerability scanning. The free plan allows weekly XSS scans
  * [Ubiq Security](https://ubiqsecurity.com/) — Encrypt and decrypt data with three lines of code and automatic key management. Free for one application and up to 1,000,000 encryptions per month.
  * [Virgil Security](https://virgilsecurity.com/) — Tools and services for implementing end-to-end encryption, database protection, IoT security, and more in your digital solution. Free for applications with up to 250 users.
  * [Vulert](https://vulert.com) - Vulert continuously monitors your open-source dependencies for new vulnerabilities, recommends fixes, without requiring installation or access to your codebase. Free for open-source projects.
  * [Escape GraphQL Quickscan](https://escape.tech/) - One-click security scan of your GraphQL endpoints. Free, no login required.
  * [HasMySecretLeaked](https://gitguardian.com/hasmysecretleaked) - Search across 20 million exposed secrets in public GitHub repositories, gists, issues,and comments for Free
  * [Project Gatekeeper](https://gatekeeper.binarybiology.top/) - An All-in-One SSL Toolkit Offering various features like Private Key & CSR Generator, SSL Certificate Decoder, Certificate Matcher and Order SSL Certificate. We offer the users to generate Free SSL Certificates from Let's Encrypt, Google Trust and BuyPass using CNAME Records rather than TXT Records.

**[⬆️ Back to Top](#table-of-contents)**

## Authentication, Authorization, and User Management

  * [Aserto](https://www.aserto.com) - Fine-grained authorization as a service for applications and APIs. Free up to 1000 MAUs and 100 authorizer instances.
  * [asgardeo.io](https://wso2.com/asgardeo) - Seamless Integration of SSO, MFA, passwordless auth and more. Includes SDKs for frontend and backend apps. Free up to 1000 MAUs and five identity providers.
  * [Auth0](https://auth0.com/) — Hosted SSO. The free plan includes 25,000 MAUs, unlimited Social Connections, a custom domain, and more.
  * [Authgear](https://www.authgear.com) - Bring Passwordless, OTPs, 2FA, SSO to your apps in minutes. All Front-end included. Free up to 5000 MAUs.
  * [Authress](https://authress.io/) — Authentication login and access control, unlimited identity providers for any project. Facebook, Google, Twitter and more. The first 1000 API calls are free.
  * [Authy](https://authy.com) - Two-factor authentication (2FA) on multiple devices, with backups. Drop-in replacement for Google Authenticator. Free for up to 100 successful authentications.
  * [Cerbos Hub](https://www.cerbos.dev/product-cerbos-hub) - A complete authorization management system for authoring, testing, and deploying access policies. Fine-grained authorization and access control, free up to 100 monthly active principals.
  * [Clerk](https://clerk.com) — User management, authentication, 2FA/MFA, prebuilt UI components for sign-in, sign-up, user profiles, and more. Free up to 10,000 monthly active users.
  * [Cloud-IAM](https://www.cloud-iam.com/) — Keycloak Identity and Access Management as a Service. Free up to 100 users and one realm.
  * [Corbado](https://www.corbado.com/) — Add passkey-first authentication to new or existing apps. Free for unlimited MAUs.
  * [Descope](https://www.descope.com/) — Highly customizable AuthN flows, has both a no-code and API/SDK approach, Free 7,500 active users/month, 50 tenants (up to 5 SAML/SSO tenants).
  * [duo.com](https://duo.com/) — Two-factor authentication (2FA) for website or app. Free for ten users, all authentication methods, unlimited, integrations, hardware tokens.
  * [Kinde](https://kinde.com/) - Simple, robust authentication you can integrate with your product in minutes.  Everything you need to get started with 7,500 free MAU.
  * [logintc.com](https://www.logintc.com/) — Two-factor authentication (2FA) by push notifications, free for ten users, VPN, Websites, and SSH
  * [MojoAuth](https://mojoauth.com/) - MojoAuth makes it easy to implement Passwordless authentication on your web, mobile, or any application in minutes.
  * [Okta](https://developer.okta.com/signup/) — User management, authentication and authorization. Free for up to 100 monthly active users.
  * [onelogin.com](https://www.onelogin.com/) — Identity as a Service (IDaaS), Single Sign-On Identity Provider, Cloud SSO IdP, three company apps, and five personal apps, unlimited users
  * [Ory](https://ory.sh/) - AuthN/AuthZ/OAuth2.0/Zero Trust managed security platform. Forever free developer accounts with all security features, unlimited team members, 200 daily active users, and 25k/mo permission checks.
  * [Permit.io](https://permit.io) - Auhtorization-as-a-service provider platform enabling RBAC, ABAC, and ReBAC for scalable microservices with real-time updates and a no-code policy UI. A 1000 Monthly Active User free tier.
  * [Phase Two](https://phasetwo.io) - Keycloak Open Source Identity and Access Management. Free realm up to 1000 users, up to 10 SSO connections, leveraging Phase Two's Keycloak enhanced container which includes the [Organization](https://phasetwo.io/product/organizations/) extension.
  * [SSOJet](https://ssojet.com/) - Add Enterprise SSO Without Rebuilding Your Auth. The free plan includes unlimited monthly active users, unlimited organizations, 2 SSO & 2 SCIM connections.
  * [Stytch](https://www.stytch.com/) - An all-in-one platform that provides APIs and SDKs for authentication and fraud prevention. The free plan includes 10,000 monthly active users, unlimited organizations, 5 SSO or SCIM connections, and 1,000 M2M tokens.
  * [Stack Auth](https://stack-auth.com) — Open-source authentication that doesn't suck. The most developer-friendly solution, getting you started in just five minutes. Self-hostable for free, or offers a managed SaaS version with 10k free Monthly Active Users.
  * [SuperTokens](https://supertokens.com/) - Open source user authentication that natively integrates into your app - enabling you to get started quickly while controlling the user and developer experience. Free for up to 5000 MAUs.
  * [Warrant](https://warrant.dev/) — Hosted enterprise-grade authorization and access control service for your apps. The free tier includes 1 million monthly API requests and 1,000 authz rules.
  * [ZITADEL Cloud](https://zitadel.com) — A turnkey user and access management that works for you and supports multi-tenant (B2B) use cases. Free for up to 25,000 authenticated requests, with all security features (no paywall for OTP, Passwordless, Policies, and so on).
  * [PropelAuth](https://propelauth.com) — A Sell to companies of any size immediately with a few lines of code, free up to 200 users and 10k Transactional Emails (with a watermark branding: "Powered by PropelAuth").
  * [Logto](https://logto.io/) - Develop, secure, and manage user identities of your product - for both authentication and authorization. Free for up to 5,000 MAUs with open-source self-hosted option available.
  * [WorkOS](https://workos.com/) - Free user management and authentication for up to 1 Million MAUs. Support email + password, social auth, Magic Auth, MFA, and more.


**[⬆️ Back to Top](#table-of-contents)**

## Mobile App Distribution and Feedback

  * [TestApp.io](https://testapp.io) - Your go-to platform for ensuring your mobile apps work as they should. Free plan: one app, analytics, unlimited versions & installs, and feedback collection.
  * [Loadly](https://loadly.io) - iOS & Android beta apps distribution service offers completely free services with unlimited downloads, high-speed downloads, and unlimited uploads.
  * [Diawi](https://www.diawi.com) - Deploy iOS & Android apps directly to devices. Free plan: app uploads, password-protected links, 1-day expiration, ten installations.
  * [InstallOnAir](https://www.installonair.com) - Distribute iOS & Android apps over the air. Free plan: unlimited uploads, private links, 2-day expiration for guests, 60 days for registered users.
  * [GetUpdraft](https://www.getupdraft.com) - Distribute mobile apps for testing. The free plan includes one app project, three app versions, 500 MB storage, and 100 app installations per month.
  * [Appho.st](https://appho.st) - Mobile app hosting platform. The free plan includes five apps, 50 monthly downloads, and a maximum file size of 100 MB.

**[⬆️ Back to Top](#table-of-contents)**

## Management System

  * [bitnami.com](https://bitnami.com/) — Deploy prepared apps on IaaS. Management of 1 AWS micro instance free
  * [Esper](https://esper.io) — MDM and MAM for Android Devices with DevOps. One hundred devices free with one user license and 25 MB Application Storage.
  * [jamf.com](https://www.jamf.com/) —  Device management for iPads, iPhones, and Macs, three devices free
  * [Miradore](https://miradore.com) — Device Management service. Stay up-to-date with your device fleet and secure unlimited devices for free. The free plan offers basic features.
  * [moss.sh](https://moss.sh) - Help developers deploy and manage their web apps and servers. Free up to 25 git deployments per month
  * [runcloud.io](https://runcloud.io/) - Server management focusing mainly on PHP projects. Free for up to 1 server.
  * [ploi.io](https://ploi.io/) - Server management tool to easily manage and deploy your servers & sites. Free for one server.
  * [xcloud.host](https://xcloud.host) — Server management and deployment platform with a user-friendly interface. Free tier available for one server.
  * [serveravatar.com](https://serveravatar.com) — Manage and monitor PHP-based web servers with automated configurations. Free for one server.

**[⬆️ Back to Top](#table-of-contents)**

## Messaging and Streaming

  * [Ably](https://www.ably.com/) - Realtime messaging service with presence, persistence and guaranteed delivery. The free plan includes 3m messages per month, 100 peak connections, and 100 peak channels.
  * [cloudamqp.com](https://www.cloudamqp.com/) — RabbitMQ as a Service. Little Lemur plan: max 1 million messages/month, max 20 concurrent connections, max 100 queues, max 10,000 queued messages, multiple nodes in different AZ's
  * [courier.com](https://www.courier.com/) — Single API for push, in-app, email, chat, SMS, and other messaging channels with template management and other features. The free plan includes 10,000 messages/mo.
  * [Engage](https://engage.so/) - All-in-one Customer Engagement and Automation Tool (email, push, SMS, product tours, banners and more) for SaaS. Free for up to 1,000 active users per month.
  * [engagespot.co](https://engagespot.co/) — Multi-channel notification infrastructure for developers with a prebuilt in-app inbox and no-code template editor. Free plan includes 10,000 messages/mo.
  * [HiveMQ](https://www.hivemq.com/mqtt-cloud-broker/) - Connect your MQTT devices to the Cloud Native IoT Messaging Broker.  Free to connect up to 100 devices (no credit card required) forever.
  * [knock.app](https://knock.app) – Notifications infrastructure for developers. Send to multiple channels like in-app, email, SMS, Slack, and push with a single API call. The free plan includes 10,000 messages/mo.
  * [NotificationAPI.com](https://www.notificationapi.com/) — Add user notifications to any software in 5 minutes. The free plan includes 10,000 notifications/month + 100 SMS and Automated Calls.
  * [Novu.co](https://novu.co) — The open-source notification infrastructure for developers. Simple components and APIs for managing all communication channels in one place: Email, SMS, Direct, In-App and Push. The free plan includes 30,000 notifications/month with 90 days of retention.
  * [pusher.com](https://pusher.com/) — Realtime messaging service. Free for up to 100 simultaneous connections and 200,000 messages/day
  * [scaledrone.com](https://www.scaledrone.com/) — Realtime messaging service. Free for up to 20 simultaneous connections and 100,000 events/day
  * [synadia.com](https://synadia.com/ngs) — [NATS.io](https://nats.io) as a service. Global, AWS, GCP, and Azure. Free forever with 4k msg size, 50 active connections, and 5GB of data per month.
  * [pubnub.com](https://www.pubnub.com/) - Swift, Kotlin, and React messaging at 1 million transactions each month. Transactions may contain multiple messages.
  * [eyeson API](https://developers.eyeson.team/) - A video communication API service based on WebRTC (SFU, MCU) to build video platforms. Allows real-time data Injection, Video Layouts, Recordings, a fully featured hosted web UI (quickstart) or packages for custom UIs. Has a [free tier for developers](https://apiservice.eyeson.com/api-pricing) with 1000 meeting minutes a month.
  * [webpushr](https://www.webpushr.com/) - Web Push Notifications - Free for upto 10k subscribers, unlimited push notifications, in-browser messaging
  * [httpSMS](https://httpsms.com) - Send and receive text messages using your Android phone as an SMS Gateway. Free to send and receive up to 200 messages per month.
  * [EMQX Serverless](https://www.emqx.com/en/cloud/serverless-mqtt) - Scalable and secure serverless MQTT broker you can get in seconds. 1M session minutes/month free forever (no credit card required).
  * [Pocket Alert](https://pocketalert.app) - Send push notifications to your iOS and Android devices. Effortlessly integrate via API or Webhooks and maintain full control over your alerts. Free plan: 50 messages per day to 1 device and 1 application.
  * [SuprSend](https://www.suprsend.com/) - SuprSend is a notification infrastructure that streamlines your product notifications with an API-first approach. Create and deliver transactional, crons, and engagement notifications on multiple channels with a single notification API. In free plan you get 10,000 notifications per month, including different workflow nodes such as digests, batches, multi-channels, preferences, tenants, broadcasts and more. 
  * [SMSGate](https://sms-gate.app) - SMS Gateway for Android™ enables sending and receiving SMS messages through your devices using cloud routing. Completely free cloud service (with recommended notification for usage above 10,000 messages/day to maintain quality for all users).

**[⬆️ Back to Top](#table-of-contents)**

## Log Management

  * [bugfender.com](https://bugfender.com/) — Free up to 100k log lines/day with 24 hours retention
  * [logentries.com](https://logentries.com/) — Free up to 5 GB/month with seven days retention
  * [loggly.com](https://www.loggly.com/) — Free for a single user, 200MB/day with seven days retention
  * [ManageEngine Log360 Cloud](https://www.manageengine.com/cloud-siem/) — Log Management service powered by Manage Engine. Free Plan offers 50 GB storage with 15 days Storage Retention and 7 days search.
  * [sumologic.com](https://www.sumologic.com/) — Free up to 500 MB/day, seven days retention
  * [log.dog](https://log.dog/) — LogDog is a remote debugging/logging SDK (iOS and Android) with a web ui. Captures all logs, requests and events in real-time and allows to intercept them. Free for up to 100MB of logs every month
  * [logflare.app](https://logflare.app/) — Free for up to 12,960,000 entries per app per month, 3 days retention
  * [logtail.com](https://logtail.com/) — ClickHouse-based SQL-compatible log management. Free up to 1 GB per month, three days retention.
  * [logzab.com](https://logzab.com/) — Audit trail management system. Free 1,000 user activity logs per month, 1-month retention, for up to 5 projects.
  * [openobserve.ai](https://openobserve.ai/) - 200 GB Ingestion/month free, 15 Days Retention

**[⬆️ Back to Top](#table-of-contents)**

## Translation Management

  * [AutoLocalise.com](https://www.autolocalise.com/) — Instantly localize without managing translation files. Free for up to 10,000 characters/month, unlimited languages.
  * [crowdin.com](https://crowdin.com/) — Unlimited projects, unlimited strings, and collaborators for Open Source
  * [gitlocalize.com](https://gitlocalize.com) - Free and unlimited for both private and public repositories
  * [Lecto](https://lecto.ai/) - Machine Translation API with Free tier (30 free requests, 1000 translated characters per request). Integrated with the Loco Translate Wordpress plugin.
  * [lingohub.com](https://lingohub.com/) — Free up to 3 users, always free for Open Source
  * [localazy.com](https://localazy.com) - Free for 1000 source language strings, unlimited languages, unlimited contributors, startup and open source deals
  * [Localeum](https://localeum.com) - Free up to 1000 strings, one user, unlimited languages, unlimited projects
  * [Localit](https://localit.io) – Fast, developer-friendly localization platform with seamless and free GitHub/GitLab integration, AI-assisted and manual translations, and a generous free plan (includes 2 users, 500 keys, and unlimited projects).
  * [localizely.com](https://localizely.com/) — Free for Open Source
  * [Loco](https://localise.biz/) — Free up to 2000 translations, Unlimited translators, ten languages/project, 1000 translatable assets/project
  * [oneskyapp.com](https://www.oneskyapp.com/) — Limited free edition for up to 5 users, free for Open Source
  * [POEditor](https://poeditor.com/) — Free up to 1000 strings
  * [SimpleLocalize](https://simplelocalize.io/) - Free up to 100 translation keys, unlimited strings, unlimited languages, startup deals
  * [Texterify](https://texterify.com/) - Free for a single user
  * [Tolgee](https://tolgee.io) - Free SaaS offering with limited translations, forever-free self-hosted version
  * [transifex.com](https://www.transifex.com/) — Free for Open Source
  * [Translation.io](https://translation.io) - Free for Open Source
  * [Translized](https://translized.com) - Free up to 1000 strings, one user, unlimited languages, unlimited projects
  * [webtranslateit.com](https://webtranslateit.com/) — Free up to 500 strings
  * [weblate.org](https://weblate.org/) — It's free for libre projects with up to 10,000 string sources for the free tier and Unlimited Self-hosted on-premises.
  * [Free PO editor](https://pofile.net/free-po-editor) — Free for everybody
  * [Lingo.dev](https://lingo.dev) – Open-source AI-powered CLI for web & mobile localization. Bring your own LLM, or use 10,000 free words every month via Lingo.dev-managed localization engine.

**[⬆️ Back to Top](#table-of-contents)**

## Monitoring

  * [alerty.ai](https://www.alerty.ai) - Free APM and monitoring for your FE, BE, DB, and more + free agent runs.
  * [appdynamics.com](https://www.appdynamics.com/) — Free for 24-hour metrics, application performance management agents limited to one Java, one .NET, one PHP, and one Node.js
  * [appneta.com](https://www.appneta.com/) — Free with 1-hour data retention
  * [appspector.com](https://appspector.com/) - Mission control for remote iOS/Android/Flutter debugging. Free for small traffic usage (64MB of logs).
  * [assertible.com](https://assertible.com) — Automated API testing and monitoring. Free plans for teams and individuals.
  * [Better Stack](https://betterstack.com/better-uptime) - Uptime monitoring, incident management, on-call scheduling/alerting, and status pages in a single product. The free plan includes ten monitors with 3-minute check frequency and status pages.
  * [bleemeo.com](https://bleemeo.com) - Free for 3 servers, 5 uptime monitors, unlimited users, unlimited dashboards, unlimited alerting rules.
  * [checklyhq.com](https://checklyhq.com) - Open source E2E / Synthetic monitoring and deep API monitoring for developers. Free plan with one user and 10k API & network / 1.5k browser check runs.
  * [cloudsploit.com](https://cloudsploit.com) — AWS security and configuration monitoring. Free: unlimited on-demand scans, unlimited users, unlimited stored accounts. Subscription: automated scanning, API access, etc.
  * [Core Web Vitals History](https://punits.dev/core-web-vitals-historical/) - Find Core Web Vitals history for a url or a website.
  * [cronitor.io](https://cronitor.io/) - Performance insights and uptime monitoring for cron jobs, websites, APIs and more. A free tier with five monitors.
  * [datadoghq.com](https://www.datadoghq.com/) — Free for up to 5 nodes
  * [deadmanssnitch.com](https://deadmanssnitch.com/) — Monitoring for cron jobs. One free snitch (monitor), more if you refer others to sign up
  * [downtimemonkey.com](https://downtimemonkey.com/) — 60 uptime monitors, 5-minute interval. Email, Slack alerts.
  * [economize.cloud](https://economize.cloud) — Economize helps demystify cloud infrastructure costs by organizing cloud resources to optimize and report the same. Free for up to $5,000 spent on Google Cloud Platform every month.
  * [elastic.co](https://www.elastic.co/solutions/apm) — Instant performance insights for JS developers. Free with 24-hour data retention
  * [fivenines.io](https://fivenines.io/) — Linux server monitoring with real‑time dashboards and alerting — free forever for up to 5 monitored servers at 60-seconds interval. No credit card required.
  * [Grafana Cloud](https://grafana.com/products/cloud/) - Grafana Cloud is a composable observability platform that integrates metrics and logs with Grafana. Free: 3 users, ten dashboards, 100 alerts, metrics storage in Prometheus and Graphite (10,000 series, 14 days retention), logs storage in Loki (50 GB of logs, 14 days retention)
  * [healthchecks.io](https://healthchecks.io) — Monitor your cron jobs and background tasks. Free for up to 20 checks.
  * [incidenthub.cloud](https://incidenthub.cloud/) — Cloud and SaaS status page aggregator - 20 monitors and 2 notification channels (Slack and Discord) are free forever.
  * [inspector.dev](https://www.inspector.dev) - A complete Real-Time monitoring dashboard in less than one minute with a free forever tier.
  * [instatus.com](https://instatus.com) - Get a beautiful status page in 10 seconds. Free forever with unlimited subs and unlimited teams.
  * [instrumentalapp.com](https://instrumentalapp.com) - Beautiful and easy-to-use application and server monitoring with up to 500 metrics and 3 hours of data visibility for free
  * [keychest.net/speedtest](https://keychest.net/speedtest) - Independent speed test and TLS handshake latency test against Digital Ocean
  * [letsmonitor.org](https://letsmonitor.org) - SSL monitoring, free for up to 5 monitors
  * [linkok.com](https://linkok.com) - Online broken link checker, free for small websites up to 100 pages, completely free for open-source projects.
  * [loader.io](https://loader.io/) — Free load testing tools with limitations
  * [Middleware.io](https://middleware.io/) -  Middleware observability platform provides complete visibility into your apps & stack, so you can monitor & diagnose issues at scale. They have a free forever plan for Dev community use that allows Log monitoring for up to 1M log events, Infrastructure monitoring & APM for up to 2 hosts.
  * [MonitorMonk](https://monitormonk.com) - Minimalist uptime monitoring with beautiful status pages. The Forever Free plan offers HTTPS, Keyword, SSL and Response-time monitorming for 10 websites or api-endpoints, and provides 2 dashboards/status pages.
  * [netdata.cloud](https://www.netdata.cloud/) — Netdata is an open-source tool to collect real-time metrics. It's a growing product and can also be found on GitHub!
  * [newrelic.com](https://www.newrelic.com) — New Relic observability platform built to help engineers create more perfect software. From monoliths to serverless, you can instrument everything and then analyze, troubleshoot, and optimize your entire software stack. The free tier offers 100GB/month of free data ingest, one free full-access user, and unlimited free primary users.
  * [nixstats.com](https://nixstats.com) - Free for one server. E-Mail Notifications, public status page, 60-second interval, and more.
  * [OnlineOrNot.com](https://onlineornot.com/) - OnlineOrNot provides uptime monitoring for websites and APIs, monitoring for cron jobs and scheduled tasks. Also provides status pages. The first five checks with a 3-minute interval are free. The free tier sends alerts via Slack, Discord, and Email.
  * [OntarioNet.ca CN Test](https://cntest.ontarionet.ca) — Check if a website is blocked in China by the Great Firewall. It identifies DNS pollution by comparing DNS results and ASN information detected by servers in China versus servers in the United States.
  * [opsgenie.com](https://www.opsgenie.com/) — Powerful alerting and on-call management for operating always-on services. Free up to 5 users.
  * [paessler.com](https://www.paessler.com/) — Powerful infrastructure and network monitoring solution, including alerting, strong visualization capabilities, and basic reporting. Free up to 100 sensors.
  * [pagecrawl.io](https://pagecrawl.io/) -  Monitor website changes, free for up to 6 monitors with daily checks.
  * [pagerly.io](https://pagerly.io/) -  Manage on-calls on Slack  (integrates with Pagerduty, OpsGenie). Free up to 1 team (one team refers to one on call)
  * [pageradar.io](https://pageradar.io/) — Monitor Core Web Vitals, SEO changes, and uptime for your websites. Free plan includes 5 URLs, daily Core Web Vitals monitoring, 10 HTML/SEO change monitors, 167-country affiliate link monitoring, and email alerts.
  * [pagertree.com](https://pagertree.com/) - Simple interface for alerting and on-call management. Free up to 5 users.
  * [phare.io](https://phare.io/) - Uptime Monitoring free for up to 100,000 events for unlimited projets and unlimited status pages.
  * [pingbreak.com](https://pingbreak.com/) — Modern uptime monitoring service. Check unlimited URLs and get downtime notifications via Discord, Slack, or email.
  * [Pingmeter.com](https://pingmeter.com/) - 5 uptime monitors with 10-minute interval. Monitor SSH, HTTP, HTTPS, and any custom TCP ports.
  * [pingpong.one](https://pingpong.one/) — Advanced status page platform with monitoring. The free tier includes one public customizable status page with an SSL subdomain. Pro plan is offered to open-source projects and non-profits free of charge.
  * [Pulsetic](https://pulsetic.com) - 10 monitors, 6 Months of historical Uptime/Logs, unlimited status pages, and custom domains included! For infinite time and unlimited email alerts for free. You don't need a credit card.
  * [robusta.dev](https://home.robusta.dev/) — Powerful Kubernetes monitoring based on Prometheus. Bring your own Prometheus or install the all-in-one bundle. The free tier includes up to 20 Kubernetes nodes. Alerts via Slack, Microsoft Teams, Discord, and more. Integrations with PagerDuty, OpsGenie, VictorOps, DataDog, and many other tools.
  * [sematext.com](https://sematext.com/) — Free for 24-hour metrics, unlimited servers, ten custom metrics, 500,000 custom metrics data points, unlimited dashboards, users, etc.
  * [Simple Observability](https://simpleobservability.com) — Powerful server monitoring in a unified platform for metrics and logs, with no setup complexity. Free for one server.
  * [sitemonki.com](https://sitemonki.com/) — Website, domain, Cron & SSL monitoring, 5 monitors in each category for free
  * [sitesure.net](https://sitesure.net) - Website and cron monitoring - 2 monitors free
  * [skylight.io](https://www.skylight.io/) — Free for first 100,000 requests (Rails only)
  * [Servervana](https://servervana.com) - Advanced uptime monitoring with support for large projects and teams. Provides HTTP monitoring, Browser based monitoring, DNS monitoring, domain monitoring, status pages and more. The free tier includes 10 HTTP monitors, 1 DNS monitor and one status page.
  * [speedchecker.xyz](https://probeapi.speedchecker.xyz/) — Performance Monitoring API, checks Ping, DNS, etc.
  * [Squadcast.com](https://squadcast.com) - Squadcast is an end-to-end incident management software designed to help you promote SRE best practices. Free forever plan available for up to 10 users.
  * [stathat.com](https://www.stathat.com/) — Get started with ten stats for free, no expiration
  * [statuscake.com](https://www.statuscake.com/) — Website monitoring, unlimited tests free with limitations
  * [statusgator.com](https://statusgator.com/) — Status page monitoring, 3 monitors free
  * [SweetUptime](https://dicloud.net/sweetuptime-server-uptime-monitoring/) — Server monitoring, uptime monitoring, DNS & domain monitoring. Monitor 10 server, 10 uptime, and 10 domain for free.
  * [syagent.com](https://syagent.com/) — Noncommercial free server monitoring service, alerts and metrics.
  * [thousandeyes.com](https://www.thousandeyes.com/) — Network and user experience monitoring. 3 locations and 20 data feeds of major web services free
  * [UptimeObserver.com](https://uptimeobserver.com) - Get 20 uptime monitors with 5-minute intervals and a customizable status page—even for commercial use. Enjoy unlimited, real-time notifications via email and Telegram. No credit card needed to get started.
  * [uptimetoolbox.com](https://uptimetoolbox.com/) — Free monitoring for five websites, 60-second intervals, public statuspage.
  * [zenduty.com](https://www.zenduty.com/) — End-to-end incident management, alerting, on-call management, and response orchestration platform for network operations, site reliability engineering, and DevOps teams. Free for up to 5 users.
  * [RoboMiri.com](https://robomiri.com/) - RoboMiri is a stable uptime monitor that offers a wide range of monitors: cronjob, keyword, website, port, ping. Twenty-five uptime checks with 3-minute interval checks for free. Alerts via Phone Call, SMS, Email, and Webhooks.
  * [Wachete](https://www.wachete.com) - monitor five pages, checks every 24 hours.
  * [Xitoring.com](https://xitoring.com/) — Uptime monitoring: 20 free, Linux and Windows Server monitoring: 5 free, Status page: 1 free - Mobile app, multiple notification channel, and much more!

**[⬆️ Back to Top](#table-of-contents)**

## Crash and Exception Handling

  * [CatchJS.com](https://catchjs.com/) - JavaScript error tracking with screenshots and click trails. Free for open-source projects.
  * [Bugsink](https://www.bugsink.com/) — Error-tracking with Sentry-SDK compatability. Free for up to 5,000 errors/month, or unlimited use when self-hosted.
  * [bugsnag.com](https://www.bugsnag.com/) — Free for up to 2,000 errors/month after the initial trial
  * [elmah.io](https://elmah.io/) — Error logging and uptime monitoring for web developers. Free Small Business subscription for open-source projects.
  * [Embrace](https://embrace.io/) — Mobile app monitoring. Free for small teams with up to 1 million user sessions per year.
  * [exceptionless](https://exceptionless.com) — Real-time error, feature, log reporting, and more. Free for 3k events per month/1 user. Open source and easy to self-host for unlimited use.
  * [GlitchTip](https://glitchtip.com/) — Simple, open-source error tracking. Compatible with open-source Sentry SDKs. 1000 events per month for free, or can self-host with no limits
  * [honeybadger.io](https://www.honeybadger.io) - Exception, uptime, and cron monitoring. Free for small teams and open-source projects (12,000 errors/month).
  * [memfault.com](https://memfault.com) — Cloud device observability and debugging platform. 100 devices free for [Nordic](https://app.memfault.com/register-nordic), [NXP](https://app.memfault.com/register-nxp), and [Laird](https://app.memfault.com/register-laird) devices.
  * [rollbar.com](https://rollbar.com/) — Exception and error monitoring, free plan with 5,000 errors/month, unlimited users, 30 days retention
  * [sentry.io](https://sentry.io/) — Sentry tracks app exceptions in real-time and has a small free plan. Free for 5k errors per month/ 1 user, unrestricted use if self-hosted
  * [Axiom](https://axiom.co/) — Store up to 0.5 TB of logs with 30-day retention. Includes integrations with platforms like Vercel and advanced data querying with email/Discord notifiers.
  * [Semaphr](https://semaphr.com) — Free all-in-one kill switch for your mobile apps.
  * [Jam](https://jam.dev) - Developer friendly bug reports in one click. Free plan with unlimited jams.
  * [Whitespace](https://whitespace.dev) – One-click bug reports straight in your browser. Free plan with unlimited recordings for personal use.

**[⬆️ Back to Top](#table-of-contents)**

## Search

  * [algolia.com](https://www.algolia.com/) — Hosted search solution with typo-tolerance, relevance, and UI libraries to easily create search experiences. The free "Build" plan includes 1M documents and 10K searches/month. Also offers [developer documentation search](https://docsearch.algolia.com/) for free.
  * [bonsai.io](https://bonsai.io/) — Free 1 GB memory and 1 GB storage
  * [CommandBar](https://www.commandbar.com/) - Unified Search Bar as-a-service, web-based UI widget/plugin that allows your users to search contents, navigations, features, etc. within your product, which helps discoverability. Free for up to 1,000 Monthly Active Users, unlimited commands.
  * [Orama Cloud](https://orama.com/pricing) — Free 3 indexes, 100K docs/index, unlimited full-text/vector/hybrid searches, 60 days analytics
  * [searchly.com](http://www.searchly.com/) — Free 2 indices and 20 MB storage
  * [easysitesearch.com](https://easysitesearch.com/) — Search widget and API, with automated web-crawler based indexing. Unlimited searches for free, for up to 50 subpages.

**[⬆️ Back to Top](#table-of-contents)**

## Education and Career Development

  * [FreeCodeCamp](https://www.freecodecamp.org/) - Open-source platform offering free courses and certifications in Data Analysis, Information Security, Web Development, and more.
  * [The Odin Project](https://www.theodinproject.com/) - Free, open-source platform with a curriculum focused on JavaScript and Ruby for web development.
  * [Free Professional Resume Templates & Editor](https://www.overleaf.com/latex/templates/tagged/cv) - Free platform with lots of Resume templates of Experienced Professionals, ready to clone and edit fully and download, ATS optimized.
  * [DeepLearning.AI Short Courses](https://www.deeplearning.ai/short-courses/) - Free short courses from industry-leading experts to get hands-on experience with the latest generative AI tools and techniques in an hour or less.
  * [LabEx](https://labex.io) - Develop skills in Linux, DevOps, Cybersecurity, Programming, Data Science, and more through interactive labs and real-world projects.
  * [Roadmap.sh](https://roadmap.sh) - Free learning roadmaps covering all aspects of development from Blockchain to UX Design.
  * [Cisco Networking Academy, Skills for All](https://skillsforall.com/) - Offers free certification-aligned courses in topics like cybersecurity, networking, and Python.
  * [MIT OpenCourseWare](https://ocw.mit.edu/) - MIT OpenCourseWare is an online publication of materials from over 2,500 MIT courses, freely sharing knowledge with learners and educators around the world. Youtube channel can be found at [@mitocw](https://www.youtube.com/@mitocw/featured)
  * [W3Schools](https://www.w3schools.com/) - Offers free tutorials on web development technologies like HTML, CSS, JavaScript, and more.
  * [Khan Academy](https://www.khanacademy.org/computing/computer-programming) - Free online guides for learning basic and advanced HTML/CSS, JavaScript and SQL.
  * [Full Stack Open](https://fullstackopen.com/en/) – Free university-level course on modern web development with React, Node.js, GraphQL, TypeScript, and more. Fully online and self-paced.
  * [edX](https://www.edx.org/) - Offers access to over 4,000 free online courses from 250 leading institutions, including Harvard and MIT, specializing in computer science, engineering, and data science.
  * [Django-tutorial.dev](https://django-tutorial.dev) - Free online guides for learning Django as their first framework & gives free dofollow backlink to articles written by users.
  * [DevNet Academy](https://devnet-academy.com/) – Free, self-paced training for the Cisco DevNet Expert / CCIE Automation certification. Covers Python Click and Flask-RESTx.

**[⬆️ Back to Top](#table-of-contents)**

## Email

  * [10minutemail](https://10minutemail.com) - Free, temporary email for testing.
  * [AhaSend](https://ahasend.com) - Transactional email service, free for 1000 emails per month, with unlimited domains, team members, webhooks and message routes in the free plan.
  * [AnonAddy](https://anonaddy.com) - Open-source anonymous email forwarding, create unlimited email aliases for free
  * [Antideo](https://www.antideo.com) — 10 API requests per hour for email verification, IP, and phone number validation in the free tier. No Credit Cards are required.
  * [Brevo](https://www.brevo.com/) — 9,000 emails/month, 300 emails/day free
  * [OneSignal](https://onesignal.com/) — 10,000 emails/month,No Credit Cards are required.
  * [Bump](https://bump.email/) - Free 10 Bump email addresses, one custom domain
  * [Burnermail](https://burnermail.io/) – Free 5 Burner Email Addresses, 1 Mailbox, 7-day Mailbox History
  * [Buttondown](https://buttondown.email/) — Newsletter service. Up to 100 subscribers free
  * [CloudMailin](https://www.cloudmailin.com/) - Incoming email via HTTP POST and transactional outbound - 10,000 free emails/month
  * [Contact.do](https://contact.do/) — Contact form in a link (bitly for contact forms)
  * [debugmail.io](https://debugmail.io/) — Easy to use testing mail server for developers
  * [DNSExit](https://dnsexit.com/) - Up to 2 Email addresses under your domain for free with 100MB of storage space. IMAP, POP3, SMTP, SPF/DKIM support.
  * [EmailLabs.io](https://emaillabs.io/en) — Send up to 9,000 Emails for free every month, up to 300 emails daily.
  * [EmailOctopus](https://emailoctopus.com) - Up to 2,500 subscribers and 10,000 emails per month free
  * [EmailJS](https://www.emailjs.com/) – This is not an entire email server; this is just an email client that you can use to send emails right from the client without exposing your credentials, the free tier has 200 monthly requests, 2 email templates, Requests up to 50Kb, Limited contacts history.
  * [EtherealMail](https://ethereal.email) - Ethereal is a fake SMTP service, mainly aimed at Nodemailer and EmailEngine users (but not limited to). It's an entirely free anti-transactional email service where messages never get delivered.
  * [Temp-Mail.org](https://temp-mail.org/en/) - Temporary / Disposable Mail Gen Utilizing a range variety of domain. Email Address refreshes everytime, the page is reloaded. It is entirely free and does not include any pricing for their services.
  * [TempMailDetector.com](https://tempmaildetector.com/) - Verify up to 200 emails a month for free and see if an email is temporary or not.
  * [Emailvalidation.io](https://emailvalidation.io) - 100 free email verifications per month
  * [FakeMailGenerator.com](https://www.fakemailgenerator.com/) - A German Temporary / Disposable Mail generator. Support 10 domain, while giving you the freedom of creating unlimited addresses. (include ads) but other than that, there is no pricing included in the service, it is entirely free.
  * [forwardemail.net](https://forwardemail.net) — Free email forwarding for custom domains. Create and forward an unlimited amount of email addresses with your domain name (**note**: You must pay if you use .casa, .cf, .click, .email, .fit, .ga, .gdn, .gq, .lat, .loan, .london, .men, .ml, .pl, .rest, .ru, .tk, .top, .work TLDs due to spam)
  * [Imitate Email](https://imitate.email) - Sandbox Email Server for testing email functionality across build/qa and ci/cd. Free accounts get 15 emails a day forever.
  * [ImprovMX](https://improvmx.com) – Free email forwarding.
  * [EForw](https://www.eforw.com) – Free email forwarding for one domain. Receive and send emails from your domain.
  * [Inboxes App](https://inboxesapp.com) — Create up to 3 temporary emails a day, then delete them when you're done from within a handy Chrome extension. Perfect for testing signup flows.
  * [inboxkitten.com](https://inboxkitten.com/) - Free temporary/disposable email inbox, with up to 3-day email auto-deletes. Open source and can be self-hosted.
  * [mail-tester.com](https://www.mail-tester.com) — Test if the email's DNS/SPF/DKIM/DMARC settings are correct, 20 free/month.
  * [dkimvalidator.com](https://dkimvalidator.com/) - Test if the email's DNS/SPF/DKIM/DMARC settings are correct, free service by roundsphere.com
  * [mailcatcher.me](https://mailcatcher.me/) — Catches mail and serves it through a web interface.
  * [mailchannels.com](https://www.mailchannels.com) - Email API with REST API and SMTP integrations, free for upto 3,000 emails/month.
  * [Mailcheck.ai](https://www.mailcheck.ai/) - Prevent users to sign up with temporary email addresses, 120 requests/hour (~86,400 per month)
  * [Mailchimp](https://mailchimp.com/) — 500 subscribers and 1,000 emails/month free.
  * [Maildroppa](https://maildroppa.com) - Up to 100 subscribers and unlimited emails as well as automations for free.
  * [MailerLite.com](https://www.mailerlite.com) — 1,000 subscribers/month, 12,000 emails/month free
  * [MailerSend.com](https://www.mailersend.com) — Email API, SMTP, 3,000 emails/month free for transactional emails
  * [mailinator.com](https://www.mailinator.com/) — Free, public email system where you can use any inbox you want
  * [Mailjet](https://www.mailjet.com/) — 6,000 emails/month free (200 emails daily sending limit)
  * [Mailnesia](https://mailnesia.com) - Free temporary/disposable email, which auto visit registration link.
  * [mailsac.com](https://mailsac.com) - Free API for temporary email testing, free public email hosting, outbound capture, email-to-slack/websocket/webhook (1,500 monthly API limit)
  * [Mailtrap.io](https://mailtrap.io/) — Fake SMTP server for development, free plan with one inbox, 100 messages, no team member, two emails/second, no forward rules.
  * [Mail7.io](https://www.mail7.io/) — Free Temp Email Addresses for QA Developers. Create email addresses instantly using Web Interface or API.
  * [Momentary Email](https://www.momentaryemail.com/) — Free Temporary Email Addresses. Read incoming emails on the website or by RSS feed.
  * [Mutant Mail](https://www.mutantmail.com/) – Free 10 Email IDs, 1 Domain, 1 Mailbox. Single Mailbox for All Email IDs.
  * [Outlook.com](https://outlook.live.com/owa/) - Free personal email and calendar.
  * [Parsio.io](https://parsio.io) — Free email parser (Forward email, extract the data, send it to your server)
  * [pepipost.com](https://pepipost.com) — 30k emails free for the first month, then the first 100 emails/day free.
  * [Plunk](https://useplunk.com) - 3K emails/month for free
  * [Postmark](https://postmarkapp.com/) - 100 emails/month free, unlimited DMARC weekly digests.
  * [Proton Mail](https://proton.me/mail) -  Free secure email account service provider with built-in end-to-end encryption. Free 1GB storage.
  * [Queuemail.dev](https://queuemail.dev) — Reliable email delivery API. Free tier (10,000 emails/per month). Send asynchronously. Use several SMTP servers. Blocklists, Logging, Tracking, Webhooks, and more.
  * [QuickEmailVerification](https://quickemailverification.com) — Verify 100 emails daily for free on a free tier along with other free APIs like DEA Detector, DNS Lookup, SPF Detector, and more.
  * [Resend](https://resend.com) - Transactional emails API for developers. 3,000 emails/month, 100 emails/day free, one custom domain.
  * [Sender](https://www.sender.net) Up to 15,000 emails/month, up to 2,500 subscribers
  * [Sendpulse](https://sendpulse.com) — 500 subscribers/month, 15,000 emails/month free
  * [SimpleLogin](https://simplelogin.io/) – Open source, self-hostable email alias/forwarding solution. Free 5 Aliases, unlimited bandwidth, unlimited reply/send. Free for educational staff (student, researcher, etc.).
  * [Substack](https://substack.com) — Unlimited free newsletter service. Start paying when you charge for it.
  * [Sweego](https://www.sweego.io/) - European transactional emails API for developers. 500 emails/day free.
  * [Takeout](https://takeout.bysourfruit.com) - A constantly updated email service that makes sending emails easy. Five hundred transactional emails/month free.
  * [temp-mail.io](https://temp-mail.io) — Free disposable temporary email service with multiple emails at once and forwarding
  * [Touchlead](https://touchlead.app) - A multi-purpose marketing automation tool, with lead management, form builder, and automation. Free for limited number of leads and automations
  * [trashmail.com](https://www.trashmail.com) - Free disposable email addresses with forwarding and automatic address expiration
  * [Tuta](https://tuta.com/) - Free secure email account service provider with built-in end-to-end encryption, no ads, no tracking. Free 1GB storage, one calendar (Tuta also have an [paid plan](https://tuta.com/pricing).). Tuta is also partially [open source](https://github.com/tutao/tutanota), so you can self-host.
  * [Verifalia](https://verifalia.com/email-verification-api) — Real-time email verification API with mailbox confirmation and disposable email address detector; 25 free email verifications/day.
  * [verimail.io](https://verimail.io/) — Bulk and API email verification service. 100 free verifications/month
  * [Zoho](https://www.zoho.com) — Started as an e-mail provider but now provides a suite of services, some of which have free plans. List of services having free plans :
     - [Email](https://zoho.com/mail) Free for 5 users. 5GB/user & 25 MB attachment limit, one domain.
     - [Zoho Assist](https://www.zoho.com/assist) — Zoho Assist's forever free plan includes one concurrent remote support license and Access to 5 unattended computer licenses for unlimited duration available for both professional and personnel use.
     - [Sprints](https://zoho.com/sprints) Free for 5 users,5 Projects & 500MB storage.
     - [Docs](https://zoho.com/docs) — Free for 5 users with 1 GB upload limit & 5GB storage. Zoho Office Suite (Writer, Sheets & Show) comes bundled.
     - [Projects](https://zoho.com/projects) — Free for 3 users, 2 projects & 10 MB attachment limit. The same plan applies to [Bugtracker](https://zoho.com/bugtracker).
     - [Connect](https://zoho.com/connect) — Team Collaboration free for 25 users with three groups, three custom apps, 3 Boards, 3 Manuals, and 10 Integrations along with channels, events & forums.
     - [Meeting](https://zoho.com/meeting) — Meetings with upto 3 meeting participants & 10 Webinar attendees.
     - [Vault](https://zoho.com/vault) — Password Management is accessible for Individuals.
     - [Showtime](https://zoho.com/showtime) — Yet another Meeting software for training for a remote session of up to 5 attendees.
     - [Notebook](https://zoho.com/notebook) — A free alternative to Evernote.
     - [Wiki](https://zoho.com/wiki) — Free for three users with 50 MB storage, unlimited pages, zip backups, RSS & Atom feed, access controls & customizable CSS.
     - [Subscriptions](https://zoho.com/subscriptions) — Recurring Billing management free for 20 customers/subscriptions & 1 user with all the payment hosting done by Zoho. The last 40 subscription metrics are stored
     - [Checkout](https://zoho.com/checkout) — Product Billing management with 3 pages & up to 50 payments.
     - [Desk](https://zoho.com/desk) — Customer Support management with three agents, private knowledge base, and email tickets. Integrates with [Assist](https://zoho.com/assist) for one remote technician & 5 unattended computers.
     - [Cliq](https://zoho.com/cliq) — Team chat software with 100 GB storage, unlimited users, 100 users per channel & SSO.
     - [Campaigns](https://zoho.com/campaigns) - Email Marketing
     - [Forms](https://zoho.com/forms) - Form Creator
     - [Sign](https://zoho.com/sign) - Paperless Signatures
     - [Surveys](https://zoho.com/surveys) - Online Surveys
     - [Bookings](https://zoho.com/bookings) - Appointment Scheduling
  * [Maileroo](https://maileroo.com) - SMTP relay and email API for developers. 5,000 emails per month, unlimited domains, free email verification, blacklist monitoring, mail tester and more.

**[⬆️ Back to Top](#table-of-contents)**

## Feature Toggles Management Platforms

  * [ConfigCat](https://configcat.com) - ConfigCat is a developer-centric feature flag service with unlimited team size, excellent support, and a reasonable price tag. Free plan up to 10 flags, two environments, 1 product, and 5 Million requests per month.
  * [Flagsmith](https://flagsmith.com) - Release features with confidence; manage feature flags across web, mobile, and server-side applications. Use our hosted API, deploy to your own private cloud, or run on-premise.
  * [GrowthBook](https://growthbook.io) - Open source feature flag and A/B testing provider with built-in Bayesian statistical analysis engine. Free for up to 3 users, unlimited feature flags and experiments.
  * [Hypertune](https://www.hypertune.com) - Type-safe feature flags, A/B testing, analytics and app configuration, with Git-style version control and synchronous, in-memory, local flag evaluation. Free for up to 5 team members with unlimited feature flags and A/B tests.
  * [Molasses](https://www.molasses.app) - Powerful feature flags and A/B testing. Free up to 3 environments with five feature flags each.
  * [Toggled.dev](https://www.toggled.dev) - Enterprise-ready, scalable multi-regional feature toggles management platform. Free plan up to 10 flags, two environments, unlimited requests. SDK, analytics dashboard, release calendar, Slack notifications, and all other features are included in the endless free plan.
  * [Statsig](https://www.statsig.com) - A robust platform for feature management, A/B testing, analytics, and more. Its generous free plan offers unlimited seats, flags, experiments, and dynamic configurations, supporting up to 1 million events per month.
  * [Abby](https://www.tryabby.com) - Open-Source feature flags & A/B testing. Configuration as Code & Fully Typed Typescript SDKs. Strong integration with Frameworks such as Next.js & React. Generous free tier and cheap scaling options.


**[⬆️ Back to Top](#table-of-contents)**

## Font

  * [dafont](https://www.dafont.com/) - The fonts presented on this website are their authors' property and are either freeware, shareware, demo versions, or public domain.
  * [Everything Fonts](https://everythingfonts.com/) - Offers multiple tools; @font-face, Units Converter, Font Hinter and Font Submitter.
  * [Font Squirrel](https://www.fontsquirrel.com/) - Freeware fonts licensed for commercial work. Hand-selected these typefaces and presented them in an easy-to-use format.
  * [Google Fonts](https://fonts.google.com/) - Many free fonts are easy and quick to install on a website via a download or a link to Google's CDN.
  * [FontGet](https://www.fontget.com/) - Has a variety of fonts available to download and sorted neatly with tags.
  * [Fontshare](https://www.fontshare.com/) - is a free fonts service. It’s a growing collection of professional-grade fonts, 100% free for personal and commercial use.
  * [Befonts](https://befonts.com/) - Provides several unique fonts for personal or commercial use.
  * [Font of web](https://fontofweb.com/) - Identify all the fonts used on a website and how they are used.
  * [Bunny](https://fonts.bunny.net) Privacy oriented Google Fonts
  * [FontsKey](https://www.fontskey.com/) - Provides free and commercial paid fonts for personal use and can enter text for quick filtering.
  * [fonts.xz.style](https://fonts.xz.style/) free and open source service for delivering font families to websites using CSS.
  * [Fontsensei](https://fontsensei.com/) Opensourced Google fonts tagged by users. With CJK (Chinese,Japanese,Korean) font tags.

**[⬆️ Back to Top](#table-of-contents)**

## Forms

  * [Feathery](https://feathery.io) - Powerful, developer-friendly form builder. Build signup & login, user onboarding, payment flows, complex financial applications, and more. The free plan allows up to 250 submissions/month and five active forms.
  * [Form-Data](https://form-data.com) - No-code forms backend. Spam filter, email notification and auto-respond, webhooks, zapier, redirects, AJAX or POST, and more. The free plan offers unlimited forms, 20 submissions/month, and an additional 2000 submissions with Form-Data badge.
  * [FabForm](https://fabform.io/) - Form backend platform for intelligent developers. The free plan allows 250 form submissions per month. Friendly modern GUI. Integrates with Google Sheets, Airtable, Slack, Email, and others.
  * [Form.taxi](https://form.taxi/) — Endpoint for HTML forms submissions. With notifications, spam blockers, and GDPR-compliant data processing. Free plan for basic usage.
  * [Formcarry.com](https://formcarry.com) - HTTP POST Form endpoint, Free plan allows 100 monthly submissions.
  * [formingo.co](https://www.formingo.co/)- Easy HTML forms for static websites. You can start for free without registering an account. The free plan allows 500 monthly submissions and a customizable reply-to email address.
  * [FormKeep.com](https://www.formkeep.com/) - Unlimited forms with 50 monthly submissions, spam protection, email notification, and a drag-and-drop designer that can export HTML. Additional features include custom field rules, teams, and integrations to Google Sheets, Slack, ActiveCampaign, and Zapier.
  * [formlets.com](https://formlets.com/) — Online forms, unlimited single page forms/month, 100 submissions/month, email notifications.
  * [formspark.io](https://formspark.io/) -  Form to Email service, free plan allows unlimited forms, 250 submissions per month, support by Customer assistance team.
  * [Formspree.io](https://formspree.io/) — Send email using an HTTP POST request. The free tier limits to 50 submissions per form per month.
  * [Formsubmit.co](https://formsubmit.co/) — Easy form endpoints for your HTML forms. Free Forever. No registration is required.
  * [Formlick.com](https://formlick.com) - Typeform alternative with lifetime deal. Users can create 1 free form and receive unlimited submissions. In premium, users can create unlimited forms and unlimited submissions.
  * [getform.io](https://getform.io/) - Form backend platform for designers and developers, 1 form, 50 submissions, Single file upload, 100MB file storage.
  * [HeroTofu.com](https://herotofu.com/) - Forms backend with bot detection and encrypted archive. Forward submissions via UI to email, Slack, or Zapier. Use your own front end. No server code is required. The free plan gives unlimited forms and 100 submissions per month.
  * [HeyForm.net](https://heyform.net/) - Drag and drop online form builder. The free tier lets you create unlimited forms and collect unlimited submissions. Comes with pre-built templates, anti-spam, and 100MB file storage.
  * [Tally.so](https://tally.so/) - 99% of all the features are free. The free tier lets you have: unlimited forms, unlimited submissions, email notifications, form logic, collect payments, file upload, custom thank you page, and many more.
  * [Hyperforms.app](https://hyperforms.app/) — Create a form to email and more in seconds and without backend code. The Personal account gives you up to 50 monthly form submissions for free.
  * [Kwes.io](https://kwes.io/) - Feature rich form endpoint. Works great with static sites. The free plan includes up to 1 website with up to 50 monthly submissions.
  * [Pageclip](https://pageclip.co/) - The free plan allows one site, one form, and 1,000 monthly submissions.
  * [Qualtrics Survey](https://qualtrics.com/free-account) — Create professional forms & survey using this first class tool. 50+ expert-designed survey templates. Free Account has a limit of 1 active survey, 100 responses/survey & 8 response types.
  * [Screeb](https://screeb.app/) - In-app surveys and product analytics for decoding user behavior. Forever free plan allows 500 monthly active users, unlimited responses and events, many integrations, export, and periodic reports.
  * [smartforms.dev](https://smartforms.dev/) - Powerful and easy form backend for your website, forever free plan allows 50 submissions per month, 250MB file storage, Zapier integration, CSV/JSON export, custom redirect, custom response page, Telegram & Slack bot, single email notifications.
  * [Survicate](https://survicate.com/) — Pull feedback from all sources and send follow-up surveys with one tool. Automatically analyze feedback and extract insights with AI. Free email, website, in-product or mobile surveys, AI survey creator, and 25 monthly responses.
  * [staticforms.xyz](https://www.staticforms.xyz/) - Integrate HTML forms easily without any server-side code for free. After the user submits the form, an email with the form content will be sent to your registered address.
  * [stepFORM.io](https://stepform.io) - Quiz and Form Builder. The free plan has five forms, up to 3 steps per form, and 50 monthly responses.
  * [Typeform.com](https://www.typeform.com/) — Include beautifully designed forms on websites.  The free plan allows only ten fields per form and 100 monthly responses.
  * [WaiverStevie.com](https://waiverstevie.com) - Electronic Signature platform with a REST API. You can receive notifications with webhooks. Free plan watermarks signed documents but allow unlimited envelopes + signatures.
  * [Web3Forms](https://web3forms.com) - Contact forms for Static & JAMStack Websites without writing backend code. The free plan allows Unlimited Forms, Unlimited Domains & 250 Submissions per month.
  * [WebAsk](https://webask.io) - Survey and Form Builder. The free plan has three surveys per account, 100 monthly responses, and ten elements per survey.
  * [Wufoo](https://www.wufoo.com/) - Quick forms to use on websites. The free plan has a limit of 100 submissions each month.
  * [Formester.com](https://formester.com) - Share and embed unique-looking forms on your website—no limits on the number of forms created or features restricted by the plan. Get up to 100 submissions every month for free.
  * [SimplePDF.eu](https://simplepdf.eu/embed) - Embed a PDF editor on your website and turn any PDF into a fillable form. The free plan allows unlimited PDFs with three submissions per PDF.
  * [forms.app](https://forms.app/) — Create online forms with powerful features like conditional logic, automatic score calculator, and AI. Collect up to 100 responses with a free plan, embed your forms on a website, or use them with a link.
  * [Qualli](https://usequalli.com) - In App Surveys, designed for mobile. Use Qualli AI to craft the perfect questions. You can try it out on our free plan, up to 500 MAU, create unlimited forms and triggers.
  * [Sprig](https://sprig.com/) - 1 In-Product Survey or Survey with Replay per month, with GPT-powered AI Analysis.
  * [feedback.fish](https://feedback.fish/) - Free plan allows collecting 25 total feedback submissions. Easy to integrate with React and Vue components provided.
  * [Vidhook](https://vidhook.io/) - Collect feedback using delightful surveys with high response rates. Free plan includes 1 active survey, 25 responses per survey and customizable templates.

**[⬆️ Back to Top](#table-of-contents)**

## Generative AI

  * [Zenable](https://zenable.io) - Instantly auto-fix outputs from tools like Cursor, Windsurf, and Copilot to meet your company's quality and compliance standards using guardrails built with Policy as Code. The free tier includes 100 tools calls per day to the MCP server and 25 free automated pull request reviews per day via the GitHub App.
  * [Keywords AI](https://keywordsai.co) - The best LLM monitoring platform. One format to call 200+ LLMs with 2 lines of code. 10,000 free requests every month and $0 for platform features!
  * [Portkey](https://portkey.ai/) - Control panel for Gen AI apps featuring an observability suite & an AI gateway. Send & log up to 10,000 requests for free every month.
  * [Braintrust](https://www.braintrustdata.com/) - Evals, prompt playground, and data management for Gen AI. Free plan gives upto 1,000 private eval rows/week.
  * [Findr](https://www.usefindr.com/) - Universal search that lets you search all your apps, at once. Search assistant that lets you answer questions using your information. Free plan offers unlimited unified search and 5 co daily co pilot queries.
  * [ReportGPT](https://ReportGPT.app) - AI Powered Writing Assistant. The entire platform is free as long as you bring your own API key.
  * [Clair](https://askclair.ai/) - Clinical AI Reference. Students have free access to the professional tool suite, which includes Open Search, Clinical Summary, Med Review, Drug Interactions, ICD-10 Codes, and Stewardship. Additionally, a free trial for the professional suite is available.
  * [Langtrace](https://langtrace.ai) - enables developers to trace, evaluate, manage prompts and datasets, and debug issues related to an LLM application’s performance. It creates open telemetry standard traces for any LLM which helps with observability and works with any observability client. Free plan offers 50K traces/month.
  * [LangWatch](https://langwatch.ai) - A LLMOps platform helping AI teams measure, monitor, and optimize LLM applications for reliability, cost-efficiency, and performance. With a powerful DSPy component, we enable seamless collaboration between engineers and non-technical teams to fine-tune and productionize GenAI products. Free plan includes all platform features, 1k traces/month and 1 workflow DSPy optimizers. [#opensource](https://github.com/langwatch/langwatch)
  * [Comet Opik](https://www.comet.com/site/products/opik/) - Evaluate, test, and ship LLM applications across your dev and production lifecycles. [#opensource](https://github.com/comet-ml/opik/)
  * [Langfuse](https://langfuse.com/) - Open-source LLM engineering platform that helps teams collaboratively debug, analyze, and iterate on their LLM applications. Free forever plan includes 50k observations per month and all platform features. [#opensource](https://github.com/langfuse/langfuse)
  * [Pollinations.AI](https://pollinations.ai/) - easy-to-use, free image generation AI with free API available. No signups or API keys required, and several option for integrating into a website or workflow. [#opensource](https://github.com/pollinations/pollinations)
  * [Othor AI](https://othor.ai/) - An AI-native fast, simple, and secure alternative to popular business intelligence solutions like Tableau, Power BI, and Looker. Othor utilizes large language models (LLMs) to deliver custom business intelligence solutions in minutes. The Free Forever plan provides one workspace with five datasource connections for one user, with no limits on analytics. [#opensource](https://github.com/othorai/othor.ai)
  * [OpenRouter](https://openrouter.ai/models?q=free) - Provides various free AI models including DeepSeek R1, V3, Llama, and Moonshot AI. These models excel in natural language processing and are suitable for diverse development needs. Note that while these models are free to use, they are subject to rate limits. Additionally, OpenRouter offers paid models for more advanced requirements, for instance Claude, OpenAI, Grok, Gemini, and Nova.
  * [Mediaworkbench.ai](https://mediaworkbench.ai) - MediaWorkbench.ai offers 100,000 free words for Azure OpenAI, DeepSeek, and Google Gemini models, enabling users to access powerful tools for code generation, deep research, and image creation.
  * [Audio Enhancer](https://voice-clone.org/tools/audio-enhancer) — AI-powered audio enhancer SaaS that removes noise and echo while preserving natural vocal clarity. totally Free: unlimited one-click enhancements, no login required, supports MP3/WAV/FLAC

**[⬆️ Back to Top](#table-of-contents)**

## CDN and Protection

  * [bootstrapcdn.com](https://www.bootstrapcdn.com/) — CDN for bootstrap, bootswatch and fontawesome.io
  * [cdnjs.com](https://cdnjs.com/) — Simple. Fast. Reliable. Content delivery at its finest. cdnjs is a free and open-source CDN service trusted by over 11% of all websites, powered by Cloudflare.
  * [developers.google.com](https://developers.google.com/speed/libraries/) — The Google Hosted Libraries is a content distribution network for the most popular Open Source JavaScript libraries
  * [Stellate](https://stellate.co/) - Stellate is a blazing-fast, reliable CDN for your GraphQL API and free for two services.
  * [jsdelivr.com](https://www.jsdelivr.com/) — A free, fast, and reliable open-source CDN. Supports npm, GitHub, WordPress, Deno, and more.
  * [Microsoft Ajax](https://docs.microsoft.com/en-us/aspnet/ajax/cdn/overview) — The Microsoft Ajax CDN hosts popular third-party JavaScript libraries such as jQuery and enables you to easily add them to your Web application
  * [ovh.ie](https://www.ovh.ie/ssl-gateway/) — Free DDoS protection and SSL certificate
  * [Skypack](https://www.skypack.dev/) — The 100% Native ES Module JavaScript CDN. Free for 1 million requests per domain per month.
  * [raw.githack.com](https://raw.githack.com/) — A modern replacement of **rawgit.com** which simply hosts file using Cloudflare
  * [section.io](https://www.section.io/) — A simple way to spin up and manage a complete Varnish Cache solution. Supposedly free forever for one site
  * [statically.io](https://statically.io/) — CDN for Git repos (GitHub, GitLab, Bitbucket), WordPress-related assets, and images
  * [toranproxy.com](https://toranproxy.com/) — Proxy for Packagist and GitHub. Never fail CD. Free for personal use, one developer, no support
  * [UNPKG](https://unpkg.com/) — CDN for everything on npm
  * [weserv](https://images.weserv.nl/) — An image cache & resize service. Manipulate images on the fly with a worldwide cache.
  * [Namecheap Supersonic](https://www.namecheap.com/supersonic-cdn/#free-plan) — Free DDoS protection
  * [Gcore](https://gcorelabs.com/) Global content delivery network, 1 TB and 1 million requests per month free and free DNS hosting
  * [CacheFly](https://portal.cachefly.com/signup/free2023) - Up to 5 TB per month of Free CDN traffic, 19 Core PoPs , 1 Domain and Universal SSL.
  * [PromoProxy](https://promoproxy.net/) - Free cloud Secure Web Gateway. Free plan includes up to 5 users and 1 GB per day.

**[⬆️ Back to Top](#table-of-contents)**

## PaaS

  * [anvil.works](https://anvil.works) - Web app development with nothing but Python. Free tier with unlimited apps and 30-second timeouts.
  * [appwrite](https://appwrite.io) - Unlimited projects with no project pausing (supports websockets) and authentication service. 1 Database, 3 Buckets, 5 Functions per project in free tier.
  * [configure.it](https://www.configure.it/) — Mobile app development platform, free for two projects, limited features but no resource limits
  * [codenameone.com](https://www.codenameone.com/) — Open source, cross-platform, mobile app development toolchain for Java/Kotlin developers. Free for commercial use with an unlimited number of projects
  * [deco.cx](https://www.deco.cx/en/dev) - Edge-native frontend platform with a visual CMS auto-generated from TypeScript code. Built-in A/B testing, content segmentation, and real-time analytics. Perfect for content-heavy and Enterprise e-commerce websites. Free up to 5k pageviews/month or open-source/personal projects.
  * [Deno Deploy](https://deno.com/deploy) - Distributed system that runs JavaScript, TypeScript, and WebAssembly at the edge worldwide. The free tier includes 100,000 requests per day and 100 GiB data transfers per month.
  * [domcloud.co](https://domcloud.co) – Linux hosting service that provides CI/CD with GitHub, SSH, and MariaDB/Postgres database. The free version has 1 GB storage and 1 GB network/month limit and is limited to a free domain.
  * [encore.dev](https://encore.dev/) — Backend framework using static analysis to provide automatic infrastructure, boilerplate-free code, and more. Includes free cloud hosting for hobby projects.
  * [flightcontrol.dev](https://flightcontrol.dev/) - Deploy web services, databases, and more on your own AWS account with a Git push style workflow. Free tier for users with 1 developer on personal GitHub repos. AWS costs are billed through AWS, but you can use credits and the AWS free tier.
  * [gigalixir.com](https://gigalixir.com/) - Gigalixir provides one free instance that never sleeps and a free-tier PostgreSQL database limited to 2 connections, 10, 000 rows and no backups for Elixir/Phoenix apps.
  * [leapcell](https://leapcell.io/) - Leapcell is a reliable distributed applications platform, providing everything you need to seamlessly support your rapid growth. The free plan includes 100k service invocations, 10k async tasks and 100k Redis commands.
  * [pipedream.com](https://pipedream.com) - An integration platform built for developers. Develop any workflow based on any trigger. Workflows are code you can run [for free](https://docs.pipedream.com/pricing/). No server or cloud resources to manage.
  * [pythonanywhere.com](https://www.pythonanywhere.com/) — Cloud Python app hosting. Beginner account is free, 1 Python web application at your-username.pythonanywhere.com domain, 512 MB private file storage, one MySQL database
  * [ampt.dev](https://getampt.com/) - Ampt lets teams build, deploy, and scale JavaScript apps on AWS without complicated configs or managing infrastructure. Free Preview plan includes 500 invocations hourly, 2,500 invocations daily and 50,000 invocations monthly. Custom domains are allowed only in the paid plans.
  * [Koyeb](https://www.koyeb.com) - Koyeb is a developer-friendly serverless platform to deploy apps globally. Seamlessly run Docker containers, web apps, and APIs with git-based deployment, native autoscaling, a global edge network, and built-in service mesh and discovery. Free Instance lets you deploy a web service in Frankfurt, Germany or Washington, D.C., US. Free Managed Postgres database available in Frankfurt (Germany), Washington, D.C. (US), and Singapore. 512MB memory, 2GB storage, and 0.1 CPU.
  * [Napkin](https://www.napkin.io/) - FaaS with 500Mb of memory, a default timeout of 15 seconds, and 5,000 free API calls/month rate-limited to 5 calls/second.
  * [Meteor Cloud](https://www.meteor.com/cloud) — Galaxy hosting. Meteor's platform-as-a-service for Meteor apps includes free MongoDB Shared Hosting and automatic SSL.
  * [Northflank](https://northflank.com) — Build and deploy microservices, jobs, and managed databases with a powerful UI, API & CLI. Seamlessly scale containers from version control and external Docker registries. The free tier includes two services, two cron jobs and 1 database.
  * [YepCode](https://yepcode.io) - All-in-one platform to connect APIs and services in a serverless environment. It brings all the agility and benefits of NoCode tools but with all the power of using programming languages. The free tier includes [1.000 yeps](https://yepcode.io/pricing/).
  * [WunderGraph](https://cloud.wundergraph.com) - An open-source platform that allows you to  quickly build, ship and manage modern APIs. Built-in CI/CD, GitHub integration, and automatic HTTPS. Up to 3 projects, 1GB egress, 300 minutes of build time per month on the [free plan](https://wundergraph.com/pricing)
  * [Zeabur](https://zeabur.com) - Deploy your services with one click. Free for three services, with US$ 5 free credits per month.
  * [mogenius](https://mogenius.com) - Easily build, deploy, and run services on Kubernetes. The free tier supports connecting a local Kubernetes with mogenius, enabling individual developers to create a production-like test environment on their machine.
  * [DeployApps](https://deployapps.dev/) - A serverless function provider offers 1 million function calls, 100GB of bandwidth, and 10 cron jobs per month for free, exclusively for non-commercial or academic use.
  * [Choreo](https://wso2.com/choreo/) - AI-native internal developer platform as a service. The free tier includes up to 5 components and $100 credits per month.

**[⬆️ Back to Top](#table-of-contents)**

## BaaS

  * [Activepieces](https://www.activepieces.com) - Build automation flows to connect several apps together in your app's backend. For example, send a Slack message or add a Google Sheet row when an event fires in your app. Free up to 5,000 tasks per month.
  * [back4app.com](https://www.back4app.com) - Back4App is an easy-to-use, flexible and scalable backend based on Parse Platform.
  * [backendless.com](https://backendless.com/) — Mobile and Web Baas, with 1 GB file storage free, push notifications of 50,000/month, and 1000 data objects in the table.
  * [bismuth.cloud](https://www.bismuth.cloud/) — Our AI will boostrap your Python API on our function runtime and hosted storage, build and host for free in our online editor or locally with your favorite tools.
  * [BMC Developer Program](https://developers.bmc.com/site/global/bmc_helix_platform/program/overview/index.gsp) — The BMC Developer Program provides documentation and resources to build and deploy digital innovations for your enterprise. Access to a comprehensive, personal sandbox that includes the platform, SDK, and a library of components that can be used to build and tailor apps.
  * [connectycube.com](https://connectycube.com) - Unlimited chat messages, p2p voice & video calls, files attachments and push notifications. Free for apps up to 1000 users.
  * [convex.dev](https://convex.dev/) - Reactive backend as a service, hosting your data (documents with relationships & serializable ACID transactions), serverless functions, and WebSockets to stream updates to various clients. Free for small projects - up to 1M records, 5M monthly function calls.
  * [darklang.com](https://darklang.com/) - Hosted language combined with editor and infrastructure. Accessible during the beta, a generous free tier is planned after beta.
  * [Firebase](https://firebase.com) — Firebase helps you build and run successful apps. Free Spark Plan offers Authentication, Hosting, Firebase ML, Realtime Database, Cloud Storage, Testlab. A/B Testing, Analytics, App Distribution, App Indexing, Cloud Messaging (FCM), Crashlytics, Dynamic Links, In-App Messaging, Performance Monitoring, Predictions, and Remote Config are always free.
  * [Flutter Flow](https://flutterflow.io) — Build your Flutter App UI without writing a single line of code. Also has a Firebase integration. The free plan includes full access to UI Builder and Free templates.
  * [getstream.io](https://getstream.io/) — Build scalable In-App Chat, Messaging, Video and audio, and Feeds in a few hours instead of weeks
  * [hasura.io](https://hasura.io/) — Hasura extends your existing databases wherever it is hosted and provides an instant GraphQL API that can be securely accessed for web, mobile, and data integration workloads. Free for 1GB/month of data pass-through.
  * [nhost.io](https://nhost.io) - Serverless backend for web and mobile apps. The free plan includes PostgreSQL, GraphQL (Hasura), Authentication, Storage, and Serverless Functions.
  * [onesignal.com](https://onesignal.com/) — Unlimited free push notifications. 10,000 email sends per month, with unlimited contacts and access to Auto Warm Up.
  * [paraio.com](https://paraio.com) — Backend service API with flexible authentication, full-text search and caching. Free for one app, 1GB of app data.
  * [pubnub.com](https://www.pubnub.com/) — Free push notifications for up to 1 million messages/month and 100 active daily devices
  * [pushbots.com](https://pushbots.com/) — Push notification service. Free for up to 1.5 million pushes/month
  * [pushcrew.com](https://pushcrew.com/) — Push notification service. Unlimited notifications for up to 2,000 Subscribers
  * [pusher.com](https://pusher.com/beams) — Free, unlimited push notifications for 2000 monthly active users. A single API for iOS and Android devices.
  * [quickblox.com](https://quickblox.com/) — A communication backend for instant messaging, video, and voice calling, and push notifications
  * [restspace.io](https://restspace.io/) - Configure a server with services for auth, data, files, email API, templates, and more, then compose into pipelines and transform data.
  * [Salesforce Developer Program](https://developer.salesforce.com/signup) — Build apps Lightning fast with drag-and-drop tools. Customize your data model with clicks. Go further with Apex code. Integrate with anything using powerful APIs. Stay protected with enterprise-grade security. Customize UI with clicks or any leading-edge web framework. Free Developer Program gives access to the full Lightning Platform.
  * [simperium.com](https://simperium.com/) — Move data everywhere instantly and automatically, multi-platform, unlimited sending and storage of structured data, max. 2,500 users/month
  * [Supabase](https://supabase.com) — The Open Source Firebase Alternative to build backends. Free Plan offers Authentication, Realtime Database & Object Storage.
  * [tyk.io](https://tyk.io/) — API management with authentication, quotas, monitoring and analytics. Free cloud offering
  * [zapier.com](https://zapier.com/) — Connect the apps you use to automate tasks. Five zaps every 15 minutes and 100 tasks/month
  * [IFTTT](https://ifttt.com) — Automate your favorite apps and devices. Free 2 Applets
  * [Integrately](https://integrately.com) — Automate tedious tasks with a single click. Free 100 Tasks, 15 Minute
Update Time, five active automations, webhooks.
  * [LeanCloud](https://leancloud.app/) — Mobile backend. 1GB of data storage, 256MB instance, 3K API requests/day, and 10K pushes/day are free. (API is very similar to Parse Platform)
  * [Claw.cloud](https://run.claw.cloud) - A PaaS platform offering $5/month in free credits for users with a GitHub account older than 180 days. Perfect for hosting apps, databases, and more. ([Signup Link with free credit](https://ap-southeast-1.run.claw.cloud/signin)).


**[⬆️ Back to Top](#table-of-contents)**

## Low-code Platform

  * [appsmith](https://www.appsmith.com/) — Low code project to build admin panels, internal tools, and dashboards. Integrates with 15+ databases and any API.
  * [Basedash](https://www.basedash.com) — Low-code platform for building internal admin panels and dashboards. Supports SQL databases and REST APIs.
  * [BudiBase](https://budibase.com/) — Budibase is an open-source low-code platform for creating internal apps in minutes. Supports PostgreSQL, MySQL, MSSQL, MongoDB, Rest API, Docker, K8s
  * [Clappia](https://www.clappia.com) — A low-code platform designed for building business process applications with customizable mobile and web apps. Offers a drag-and-drop interface, features like Offline Support, real-time location tracking and integration with various third-party services
  * [DronaHQ](https://www.dronahq.com/) — DronaHQ - a low code platform that helps engineering teams and product managers to build internal tools, custom user journeys, digital experiences, automation, custom admin panels, operational apps 10X faster.
  * [lil'bots](https://www.lilbots.io/) - write and run scripts online utilizing free built-in APIs like OpenAI, Anthropic, Firecrawl and others. Great for building AI agents / internal tooling and sharing with team. Free-tier includes full access to APIs, AI coding assistant and 10,000 execution credits / month.
  * [Mendix](https://www.mendix.com/) — Rapid Application Development for Enterprises, unlimited accessible sandbox environments supporting total users, 0.5 GB storage and 1 GB RAM per app. Also, Studio and Studio Pro IDEs are allowed in the free tier.
  * [outsystems.com](https://www.outsystems.com/) — Enterprise web development PaaS for on-premise or cloud, free "personal environment" offering allows for unlimited code and up to 1 GB database
  * [ReTool](https://retool.com/) — Low-code platform for building internal applications. Retool is highly hackable. If you can write it with JavaScript and an API, you can make it in Retool. The free tier allows up to five users per month, unlimited apps and API connections.
  * [Superblocks](https://superblocks.com/) — Open enterprise application platform designed for developers and semi-technical teams. Use AI to generate, edit visually and extend with code. Govern centrally with integrations, authentication, permissions & audit logs.
  * [ToolJet](https://www.tooljet.com/) — Extensible low-code framework for building business applications. Connect to databases, cloud storages, GraphQL, API endpoints, Airtable, etc., and build apps using drag-and-drop application builder.
  * [UI Bakery](https://uibakery.io) — Low-code platform that enables faster building of custom web applications. Supports building UI using drag and drop with a high level of customization through JavaScript, Python, and SQL. Available as both cloud and self-hosted solutions. Free for up to 5 users.
  * [manubes](https://www.manubes.com) - Powerful no-code cloud platform with a focus on industrial production management. Free for one user with 1 million workflow activities a month ([also available in german](https://www.manubes.de)).

**[⬆️ Back to Top](#table-of-contents)**

## Web Hosting
  * [Alwaysdata](https://www.alwaysdata.com/) — 100 MB free web hosting with support for MySQL, PostgreSQL, CouchDB, MongoDB, PHP, Python, Ruby, Node.js, Elixir, Java, Deno, custom web servers, access via FTP, WebDAV and SSH; mailbox, mailing list and app installer included.
  * [Awardspace.com](https://www.awardspace.com) — Free web hosting + a free short domain, PHP, MySQL, App Installer, Email Sending & No Ads.
  * [Bohr](https://bohr.io) — Free for non commercial projects + Developer-First Deployment and Development Platform that minimizes infrastructure hassle and speed up setup.
  * [Bubble](https://bubble.io/) — Visual programming to build web and mobile apps without code, free with Bubble branding.
  * [dAppling Network](https://www.dappling.network/) - Decentralized web hosting platform for Web3 frontends focusing on increasing uptime and security and providing an additional access point for users.
  * [DigitalOcean](https://www.digitalocean.com/pricing) - Build and deploy three static sites for free on the App Platform Starter tier.
  * [Drive To Web](https://drv.tw) — Host directly to the web from Google Drive & OneDrive. Static sites only. Free forever. One site per Google/Microsoft account.
  * [Fenix Web Server](https://preview.fenixwebserver.com) - A developer desktop app for hosting sites locally and sharing them publically (in real-time). Work however you like, using its beautiful user interface, API, and/or CLI.
  * [Free Hosting](https://freehostingnoads.net/) — Free Hosting With PHP 5, Perl, CGI, MySQL, FTP, File Manager, POP E-Mail, free sub-domains, free domain hosting, DNS Zone Editor, Web Site Statistics, FREE Online Support and many more features not offered by other free hosts.
  * [Freehostia](https://www.freehostia.com) — FreeHostia offers free hosting services incl. an industry-best Control Panel & a 1-click installation of 50+ free apps. Instant setup. No forced ads.
  * [HelioHost](https://heliohost.org) — Non-profit free web hosting with Plesk control panel, PHP, Node.js, Python, Django, Flask, .NET, Perl, CGI, MySQL, PostgreSQL, SQLite, IMAP/POP3/SMTP email, unlimited bandwidth, free subdomains, 1000 MB storage for free with the option to upgrade.
  * [Kinsta Static Site Hosting](https://kinsta.com/static-site-hosting/) — Deploy up to 100 static sites for free, custom domains with SSL, 100 GB monthly bandwidth, 260+ Cloudflare CDN locations.
  * [Lecturify](https://www.lecturify.net/index.en.html) - Web hosting with SFTP access for file upload and download, php available.
  * [Neocities](https://neocities.org) — Static, 1 GB free storage with 200 GB Bandwidth.
  * [Netlify](https://www.netlify.com/) — Builds, deploys and hosts static site/app free for 300 credits/month (equals 30 GB bandwidth).
  * [PandaStack](https://www.pandastack.io/) — An eco-system for developers includes web hosting in different formats (static web hosting, container based web hosting, wordpress and so many other managed apps available in couple of clicks ). One free web hosting (static or containered) and one free database with 100GB Bandwidth and 300 Build mins/month. 
  * [pantheon.io](https://pantheon.io/) — Drupal and WordPress hosting, automated DevOps, and scalable infrastructure. Free for developers and agencies. No custom domain.
  * [readthedocs.org](https://readthedocs.org/) — Free documentation hosting with versioning, PDF generation, and more
  * [render.com](https://render.com) — Unified cloud to build and run apps and sites with free SSL, a global CDN, private networks, auto-deploys from Git, and completely free plans for web services, databases, and static web pages.
  * [SourceForge](https://sourceforge.net/) — Find, Create, and Publish Open Source software for free
  * [surge.sh](https://surge.sh/) — Static web publishing for Front-End developers. Unlimited sites with custom domain support
  * [telegra.ph](https://telegra.ph/) Easily create web page using Quill
  * [tilda.cc](https://tilda.cc/) — One site, 50 pages, 50 MB storage, only the main pre-defined blocks among 170+ available, no fonts, no favicon, and no custom domain
  * [Vercel](https://vercel.com/) — Build, deploy, and host web apps with free SSL, global CDN, and unique Preview URLs each time you `git push`. Perfect for Next.js and other Static Site Generators.
  * [Versoly](https://versoly.com/) — SaaS-focused website builder - unlimited websites, 70+ blocks, five templates, custom CSS, favicon, SEO and forms. No custom domain.
  * [Qoddi](https://qoddi.com) - PaaS service similar to Heroku with a developer-centric approach and all-inclusive features. Free tier for static assets, staging, and developer apps.
  * [FreeFlarum](https://freeflarum.com/) - Community-powered free Flarum hosting for up to 250 users (donate to remove the watermark from the footer).
  * [MDB GO](https://mdbgo.com/) - Free hosting for one project with two weeks Container TTL, 500 MB RAM per project, SFTP - 1G disk space.
  * [Patr Cloud](https://patr.cloud/) — An easy-to-use cloud platform, among its paid services it offers to host three static sites for free.
  * [Serv00.com](https://serv00.com/) — 3 GB of free web hosting with daily backups (7 days). Support: Crontab jobs, SSH access, repositories (GIT, SVN, and Mercurial), support: MySQL, PostgreSQL, MongoDB, PHP, Node.js, Python, Ruby, Java, Perl, TCL/TK, Lua, Erlang, Rust, Pascal, C, C++, D, R, and many more.
  - [Sevalla](https://sevalla.com/) - Hosting platform designed to simplify the deployment and management of applications, databases, and static websites - 1GB site limit, 100GB free bandwidth, 600 free build minutes, 100 sites per account.

**[⬆️ Back to Top](#table-of-contents)**

## DNS

  * [1.1.1.1](https://developers.cloudflare.com/1.1.1.1/) - Free public DNS Resolver, which is fast and secure (encrypt your DNS query), provided by Cloudflare. Useful to bypass your internet provider's DNS blocking, prevent DNS query spying, and [to block adult & malware content](https://developers.cloudflare.com/1.1.1.1/1.1.1.1-for-families). It can also be used [via API](https://developers.cloudflare.com/1.1.1.1/encrypted-dns/dns-over-https/make-api-requests). Note: Just a DNS resolver, not a DNS hoster.
  * [1984.is](https://www.1984.is/product/freedns/) — Free DNS service with API and lots of other free DNS features included.
  * [cloudns.net](https://www.cloudns.net/) — Free DNS hosting up to 1 domain with 50 records
  * [deSEC](https://desec.io) - Free DNS hosting with API support, designed with security in mind. Runs on open-source software and is supported by [SSE](https://www.securesystems.de/).
  * [dns.he.net](https://dns.he.net/) — Free DNS hosting service with Dynamic DNS Support
  * [Zonomi](https://zonomi.com/) — Free DNS hosting service with instant DNS propagation. Free plan: 1 DNS zone (domain name) with up to 10 DNS records.
  * [dnspod.com](https://www.dnspod.com/) — Free DNS hosting.
  * [duckdns.org](https://www.duckdns.org/) — Free DDNS with up to 5 domains on the free tier. With configuration guides for various setups.
  * [Dynv6.com](https://dynv6.com/) — Free DDNS service with [API support](https://dynv6.com/docs/apis) and management of a lot of dns record types (like CNAME, MX, SPF, SRV, TXT and others).
  * [freedns.afraid.org](https://freedns.afraid.org/) — Free DNS hosting. Also, provide free subdomains based on numerous public user [contributed domains](https://freedns.afraid.org/domain/registry/). Get free subdomains from the "Subdomains" menu after signing up.
  * [luadns.com](https://www.luadns.com/) — Free DNS hosting, three domains, all features with reasonable limits
  * [namecheap.com](https://www.namecheap.com/domains/freedns/) — Free DNS. No limit on the number of domains
  * [nextdns.io](https://nextdns.io) - DNS-based firewall, 300K free queries monthly
  * [noip.at](https://noip.at/) — Free DDNS service without registration, tracking, logging or advertising. No limit to domains.
  * [noip](https://www.noip.com/) — a dynamic DNS service that allows up to 3 hostnames free with confirmation every 30 days
  * [sslip.io](https://sslip.io/) — Free DNS service that when queried with a hostname with an embedded IP address returns that IP address.
  * [zilore.com](https://zilore.com/en/dns) — Free DNS hosting for 5 domains.
  * [zoneedit.com](https://www.zoneedit.com/free-dns/) — Free DNS hosting with Dynamic DNS Support.
  * [zonewatcher.com](https://zonewatcher.com) — Automatic backups and DNS change monitoring. One domain free
  * [huaweicloud.com](https://www.huaweicloud.com/intl/en-us/product/dns.html) – Free DNS hosting by Huawei
  * [Hetzner](https://www.hetzner.com/dns-console) – Free DNS hosting from Hetzner with API support.
  * [Glauca](https://docs.glauca.digital/hexdns/) – Free DNS hosting for up to 3 domains and DNSSEC support
  * [VolaryDDNS](https://volaryddns.net) - Free high-performant DDNS with no subscriptions or advertisements
  * [LocalCert](https://localcert.net) - Free `.localcert.net` subdomains compatible with public CAs for use with-in private networks

**[⬆️ Back to Top](#table-of-contents)**

## Domain

  * [pp.ua](https://nic.ua/) — Free pp.ua subdomains.
  * [us.kg](https://nic.us.kg/) - Free us.kg subdomains.

**[⬆️ Back to Top](#table-of-contents)**

## IaaS

  * [4EVERLAND](https://www.4everland.org/) — Compatible with AWS S3 - APIs, interface operations, CLI, and other upload methods, upload and store files from the IPFS and Arweave networks in a safe, convenient, and efficient manner. Registered users can get 6 GB of IPFS storage and 300MB of Arweave storage for free. Any Arweave file uploads smaller than 150 KB are free.
  * [backblaze.com](https://www.backblaze.com/b2/) — Backblaze B2 cloud storage. Free 10 GB (Amazon S3-like) object storage for unlimited time
  * [filebase.com](https://filebase.com/) - S3 Compatible Object Storage Powered by Blockchain. 5 GB free storage for an unlimited duration.
  * [Tebi](https://tebi.io/) - S3 compatibility object storage.Free 25 GB storage and 250GB outbound transfer.
  * [Idrive e2](https://www.idrive.com/e2/) - S3 compatibility object storage. 10 GB free storage and 10 GB download bandwidth per month.
  * [C2 Object Storage](https://c2.synology.com/en-us/pricing/object-storage) - S3 compatibility object storage. 15 GB free storage and 15 GB downloads per month.

**[⬆️ Back to Top](#table-of-contents)**

## Managed Data Services

  * [Aiven](https://aiven.io/) - Aiven offers free PostgreSQL, MySQL and Valkey (Redis compatible) plans on its open-source data platform. Single node, 1 CPU, 1GB RAM, and for PostgreSQL and MySQL, 1GB storage. Easy migration to more extensive plans or across clouds.
  * [airtable.com](https://airtable.com/) — Looks like a spreadsheet, but it's a relational database unlimited bases, 1,200 rows/base, and 1,000 API requests/month
  * [Astra](https://www.datastax.com/products/datastax-astra/) — Cloud Native Cassandra as a Service with [80GB free tier](https://www.datastax.com/products/datastax-astra/pricing)
  * [codehooks.io](https://codehooks.io/) — Easy to use JavaScript serverless API/backend and NoSQL database service with functions, Mongdb-ish queries, key/value lookups, a job system, realtime messages, worker queues, a powerful CLI and a web-based data manager. Free plan has 5GB storage and 60/API calls per minute. 2 developers included. No credit-card required.
  * [CrateDB](https://crate.io/) - Distributed Open Source SQL database for real-time analytics. [Free Tier CRFREE](https://crate.io/lp-crfree): One-node with 2 CPUs, 2 GiB of memory, 8 GiB of storage. One cluster per organization, no payment method needed.
  * [Upstash](https://upstash.com/) — Serverless Redis with free tier up to 10,000 requests per day, 256MB max database size, and 20 concurrent connections
  * [Couchbase Capella](https://www.couchbase.com/products/capella/) - deploy a forever free tier fully managed database cluster built for developers to create the next generation of applications across IoT to AI
  * [MongoDB Atlas](https://www.mongodb.com/cloud/atlas) — free tier gives 512 MB
  * [redsmin.com](https://www.redsmin.com/) — Online real-time monitoring and administration service for Redis, Monitoring for 1 Redis instance free
  * [redislabs](https://redislabs.com/try-free/) - Free 30MB redis instance
  * [MemCachier](https://www.memcachier.com/) — Managed Memcache service. Free for up to 25MB, 1 Proxy Server, and basic analytics
  * [scalingo.com](https://scalingo.com/) — Primarily a PaaS but offers a 128MB to 192MB free tier of MySQL, PostgreSQL, or MongoDB
  * [SeaTable](https://seatable.io/) — Flexible, Spreadsheet-like Database built by the Seafile team. unlimited tables, 2,000 lines, 1-month versioning, up to 25 team members.
  * [skyvia.com](https://skyvia.com/) — Cloud Data Platform offers a free tier and all plans are completely free while in beta
  * [StackBy](https://stackby.com/) — One tool that combines spreadsheets' flexibility, databases' power, and built-in integrations with your favorite business apps. The free plan includes unlimited users, ten stacks, and a 2GB attachment per stack.
  * [TiDB Cloud](https://en.pingcap.com/tidb-cloud/) — TiDB is an open-source MySQL-compatible distributed HTAP RDBMS. TiDB Serverless provides 5GB of row storage, 5GB of column storage, and 50 million Request Units (RUs) for free each month.
  * [Turso by ChiselStrike](https://chiselstrike.com/) - Turso is SQLite Developer Experience in an Edge Database. Turso provides a Free Forever starter plan, 9 GB of total storage, Up to 500 databases, Up to 3 locations, 1 billion row reads per month, and Local development support with SQLite.
  * [InfluxDB](https://www.influxdata.com/) — Timeseries database, free up to 3MB/5 minutes writes, 30MB/5 minutes reads and 10,000 cardinalities series
  * [restdb.io](https://restdb.io/) - a fast and straightforward NoSQL cloud database service. With restdb.io you get schema, relations, automatic REST API (with MongoDB-like queries), and an efficient multi-user admin UI for working with data. The free plan allows 3 users, 2500 records, and 1 API request per second.
  * [CockroachDB Cloud](https://www.cockroachlabs.com/pricing/) — Free tier offers 50 million RUs and 10 GiB of storage (same as 15$ worth) free per month. ([What's the Request Units](https://www.cockroachlabs.com/docs/cockroachcloud/metrics-request-units.html))
  * [Neo4j Aura](https://neo4j.com/cloud/aura/) — Managed native Graph DBMS / analytics platform with a Cypher query language and a REST API. Limits on graph size (50k nodes, 175k relationships).
  * [Neon](https://neon.tech/) — Managed PostgreSQL, 0.5 GB of storage (total), 1 Project ,10 branches, Unlimited Databases, always-available primary branch ( Auto suspend after 5 minutes), 20 hours of Active time per month (total) for non-primary branch compute.
  * [Prisma Postgres](https://prisma.io/postgres) - Super fast hosted Postgres built on unikernels and running on bare metal, 1GB storage, 10 databases, integrated with Prisma ORM.
  * [Dgraph Cloud](https://cloud.dgraph.io/pricing?type=free) — Managed native Graph DBMS with a GraphQL API. Limited to 1 MB data transfer per day.
  * [Tinybird](https://tinybird.co) - A serverless managed ClickHouse with connection-less data ingest over HTTP and lets you publish SQL queries as managed HTTP APIs. There is no time limit on free-tier, 10GB storage + 1000 API requests per day.
  * [TigerGraph Cloud](https://www.tigergraph.com/cloud/) — Managed native Graph DBMS / analytics platform with a SQL-like graph query language and a REST API. One free instance with two vCPU, 8GB Memory, and 50GB storage that sleeps after 1 hour of inactivity.
  * [TerminusCMS](https://terminusdb.com/pricing) — Managed free service for TerminusDB, a document and graph database written in Prolog and Rust. Free for dev, paid service for enterprise deployments and support.
  * [filess.io](https://filess.io) - filess.io is a platform where you can create two databases with up to 10 MB per database of the following DBMS for free: MySQL, MariaDB, MongoDB, and PostgreSQL.
  * [xata.io](https://xata.io) - Xata is a serverless database with built-in powerful search and analytics. One API, multiple type-safe client libraries, and optimized for your development workflow. The free-forever tier is sufficient for hobby developers which comes with three units of Xata, please refer to the website for unit definition.
  * [8base.com](https://www.8base.com/) - 8base is a full-stack low-code development platform built for JavaScript developers built on top of MySQL and GraphQL and serverless backend-as-a-service. It allows you to start building web applications quickly using a UI app builder and scale quickly, The Free tier includes rows: 2,500, Storage: 500, Serverless computing: 1Gb/h, and client app users: 5.
  * [Nile](https://www.thenile.dev/) — A Postgres platform for B2B apps. Unlimited databases, Always available with no shutdown, 1GB of storage (total), 50 million query tokens, autoscaling, unlimited vector embeddings



**[⬆️ Back to Top](#table-of-contents)**

## Tunneling, WebRTC, Web Socket Servers and Other Routers

  * [Pinggy](https://pinggy.io) — Public URLs for localhost with a single command, no downloads required. HTTPS / TCP / TLS tunnels. The free plan has 60 minutes tunnel lifetime.
  * [conveyor.cloud](https://conveyor.cloud/) — Visual Studio extension to expose IIS Express to the local network or over a tunnel to a public URL.
  * [Hamachi](https://www.vpn.net/) — LogMeIn Hamachi is a hosted VPN service that lets you securely extend LAN-like networks to distributed teams with a free plan that allows unlimited networks with up to 5 people
  * [Mirna Sockets](https://mirna.cloud/) - Free Socket as a Service Platform that gives you a wss:// URL when deploying your Web Socket Server code and also allows you to monitor its performance.
  * [localhost.run](https://localhost.run/) — Expose locally running servers over a tunnel to a public URL.
  * [localtunnel](https://theboroer.github.io/localtunnel-www/) — Expose locally running servers over a tunnel to a public URL. Free hosted version, and [open source](https://github.com/localtunnel/localtunnel).
  * [ngrok.com](https://ngrok.com/) — Expose locally running servers over a tunnel to a public URL.
  * [cname.dev](https://cname.dev/) — Free and secure dynamic reverse proxy service.
  * [serveo](https://serveo.net/) — Expose local servers to the internet. No installation, no signup. Free subdomain, no limits.
  * [Radmin VPN](https://www.radmin-vpn.com/) — Connect multiple computers together via a VPN-enabling LAN-like network. Unlimited peers. (Hamachi alternative)
  * [segment.com](https://segment.com/) — Hub to translate and route events to other third-party services. 100,000 events/month free
  * Google STUN — [stun:stun.l.google.com:19302](stun:stun.l.google.com:19302)
  * Twilio STUN — [stun:global.stun.twilio.com:3478?transport=udp](stun:global.stun.twilio.com:3478?transport=udp)
  * [Tailscale](https://tailscale.com/) — Zero config VPN, using the open-source WireGuard protocol. Installs on MacOS, iOS, Windows, Linux, and Android devices. Free plan for personal use with 100 devices and three users.
  * [webhookrelay.com](https://webhookrelay.com) — Manage, debug, fan-out, and proxy all your webhooks to public or internal (i.e. localhost) destinations. Also, expose servers running in a private network over a tunnel by getting a public HTTP endpoint (`https://yoursubdomain.webrelay.io <----> http://localhost:8080`).
  * [Hookdeck](https://hookdeck.com/pricing) — Develop, test, and monitor your webhooks from anywhere. 100K requests and 100K attempts per month with three days retention.
  * [Xirsys](https://www.xirsys.com/pricing/) — Unlimited STUN usage + 500 MB monthly TURN bandwidth, capped bandwidth, single geographic region.
  * [ZeroTier](https://www.zerotier.com) — FOSS managed virtual Ethernet as a service. Unlimited end-to-end encrypted networks of 25 clients on the free plan. Clients for desktop/mobile/NA; web interface for configuration of custom routing rules and approval of new client nodes on private networks
  * [LocalXpose](https://localxpose.io) — Reverse proxy that enables you to expose your localhost servers to the internet. The free plan has 15 minutes tunnel lifetime.
  * [Traefik-Hub](https://traefik.io/traefik-hub/) - Publish locally, running services over a tunnel to a public custom URL and secure them with access control. Free for 5 services in one cluster.
  * [Expose](https://expose.dev/) - Expose local sites via secure tunnels. The free plan includes an EU Server, Random subdomains, and Single users.
  * [btunnel](https://www.btunnel.in/) — Expose localhost and local tcp server to the internet. Free plan includes file server, custom http request and response headers, basic auth protection and 1 hour tunnel timeout.

**[⬆️ Back to Top](#table-of-contents)**

## Issue Tracking and Project Management

  * [acunote.com](https://www.acunote.com/) — Free project management and SCRUM software for up to 5 team members
  * [asana.com](https://asana.com/) — Free for private project with collaborators
  * [Backlog](https://backlog.com) — Everything your team needs to release great projects in one platform. The free plan offers 1 Project with ten users & 100MB of storage.
  * [Basecamp](https://basecamp.com/personal) - To-do lists, milestone management, forum-like messaging, file sharing, and time tracking. Up to 3 projects, 20 users, and 1GB of storage space.
  * [bitrix24.com](https://www.bitrix24.com/) — Intranet and project management tool. The free plan has 5GB for unlimited users.
  * [cacoo.com](https://cacoo.com/) — Online real-time diagrams: flowchart, UML, network. Free max. 15 users/diagram, 25 sheets
  * [Chpokify](https://chpokify.com/) — Teams-based Planning Poker that saves time on sprint estimation. Free up to 5 users, free Jira integrations, unlimited video calls, unlimited teams, unlimited sessions.
  * [clickup.com](https://clickup.com/) — Project management. Free, premium version with cloud storage. Mobile applications and Git integrations are available.
  * [Clockify](https://clockify.me) - Time tracker and timesheet app that lets you track work hours across projects. Unlimited users, free forever.
  * [Cloudcraft](https://cloudcraft.co/) — Design a professional architecture diagram in minutes with the Cloudcraft visual designer, optimized for AWS with intelligent components that show live data too. Free plan has unlimited private diagrams for single user.
  * [Codegiant](https://codegiant.io) — Project Management with Repository hosting & CI/CD. Free Plan Offers Unlimited Repositories, Projects & Documents with 5 Team Members. 500 CI/CD minutes per month. 30000 Serverless Code Run minutes per month 1GB repository storage.
  * [Confluence](https://www.atlassian.com/software/confluence) - Atlassian's content collaboration tool is used to help teams collaborate and share knowledge efficiently. Free plan for up to 10 users.
  * [contriber.com](https://www.contriber.com/) — Customizable project management platform, free starter plan, five workspaces
  * [Crosswork](https://crosswork.app/) - Versatile project management platform. Free for up to 3 projects, unlimited users, 1 GB storage.
  * [diagrams.net](https://app.diagrams.net/) — Online diagrams stored locally in Google Drive, OneDrive, or Dropbox. Free for all features and storage levels
  * [freedcamp.com](https://freedcamp.com/) - tasks, discussions, milestones, time tracking, calendar, files and password manager. Free plan with unlimited projects, users, and file storage.
  * [easyretro.io](https://www.easyretro.io/) — Simple and intuitive sprint retrospective tool. The free plan has three public boards and one survey per board per month.
  * [GForge](https://gforge.com) — Project Management and issue Tracking toolset for complex projects with self-premises and SaaS options. SaaS free plan offers the first five users free & free for Open Source Projects.
  * [gleek.io](https://www.gleek.io) — Free description-to-diagrams tool for developers. Create informal UML class, object, or entity-relationship diagrams using your keyword.
  * [GraphQL Inspector](https://github.com/marketplace/graphql-inspector) - GraphQL Inspector outputs a list of changes between two GraphQL schemas. Every difference is precisely explained and marked as breaking, non-breaking, or dangerous.
  * [Hygger](https://hygger.io) — Project management platform. The free plan offers unlimited users, projects & boards with 100 MB of Storage.
  * [Instabug](https://instabug.com) —  A comprehensive bug reporting and in-app feedback SDK for mobile apps. Free plan up to 1 app and one member.
  * [WishKit](https://wishkit.io) —  Collect in-app user feedback for your iOS/macOS app and prioritize features based on user votes. Free plan up to 1 app.
  * [Ilograph](https://www.ilograph.com/)  — interactive diagrams that allow users to see their infrastructure from multiple perspectives and levels of detail. Charts can be expressed in code. The free tier has unlimited private diagrams with up to 3 viewers.
  * [Jira](https://www.atlassian.com/software/jira) — Advanced software development project management tool used in many corporate environments. Free plan for up to 10 users.
  * [kanbanflow.com](https://kanbanflow.com/) — Board-based project management. Free, premium version with more options
  * [kanbantool.com](https://kanbantool.com/) — Kanban board-based project management. The free plan has two boards and two users, without attachments or files.
  * [kan.bn](https://kan.bn/) - A powerful, flexible kanban app that helps you organise work, track progress, and deliver results—all in one place. Free plan up to 1 user for unlimited boards, unlimited lists, unlimited cards.
  * [Kitemaker.co](https://kitemaker.co) - Collaborate through all phases of the product development process and keep track of work across Slack, Discord, Figma, and Github. Unlimited users, unlimited spaces. Free plan up to 250 work items.
  * [Kiter.app](https://www.kiter.app/) - Let anyone organize their job search and track interviews, opportunities, and connections. Powerful web app and Chrome extension. Completely free.
  * [Kumu.io](https://kumu.io/)  — Relationship maps with animation, decorations, filters, clustering, spreadsheet imports, etc. The free tier allows unlimited public projects. Graph size unlimited. Free private projects for students. Sandbox mode is available if you prefer not to leave your file publicly online (upload, edit, download, discard).
  * [Linear](https://linear.app/) — Issue tracker with a streamlined interface. Free for unlimited members, up to 10MB file upload size, 250 issues (excluding Archive)
  * [leiga.com](https://www.leiga.com/) — Leiga is a SaaS product that uses AI to automatically manage your projects, helping your team stay focused and unleash immense potential, ensuring your projects progress as planned. Free for up to 10 users, 20 custom fields, 2GB of storage space, Video Recording with AI limited to 5 mins/video, Automation Runs at 20/user/month.
  * [Lucidchart](https://www.lucidchart.com/) - An online diagram tool with collaboration features. Free plan with three editable documents, 100 professional templates, and basic collaboration features.
  * [MeisterTask](https://www.meistertask.com/) — Online task management for teams. Free up to 3 projects and unlimited project members.
  * [MeuScrum](https://www.meuscrum.com/en) - Free online scrum tool with kanban board
  * [nTask](https://www.ntaskmanager.com/) — Project management software that enables your teams to collaborate, plan, analyze, and manage everyday tasks. The essential plan is free forever with 100 MB storage and five users/teams. Unlimited workspaces, meetings, assignments, timesheets, and issue tracking.
  * [Ora](https://ora.pm/) - Agile task management & team collaboration. Free for up to 3 users and files are limited to 10 MB.
  * [pivotaltracker.com](https://www.pivotaltracker.com/) — Free for unlimited public projects and two private projects with three total active users (read-write) and unlimited passive users (read-only).
  * [plan.io](https://plan.io/) — Project Management with Repository Hosting and more options. Free for two users with ten customers and 500MB Storage
  * [Plane](https://plane.so/) - Plane is a simple, extensible, open-source project and product management tool. Free for unlimited members, up to 5MB file upload size, 1000 issues.
  * [planitpoker.com](https://www.planitpoker.com/) — Free online planning poker (estimation tool)
  * [point.poker](https://www.point.poker/) - Online Planning Poker (consensus-based estimation tool). Free for unlimited users, teams, sessions, rounds, and votes. You don't need to register.
  * [ScrumFast](https://www.scrumfast.com) - Scrum board with a very intuitive interface, free up to 5 users.
  * [Shake](https://www.shakebugs.com/) - In-app bug reporting and feedback tool for mobile apps. Free plan, ten bug reports per app/month.
  * [Shortcut](https://shortcut.com/) - Project management platform. Free for up to 10 users forever.
  * [Tadum](https://tadum.app) - Meeting agenda and minutes app designed for recurring meetings, free for teams of up to 10
  * [taiga.io](https://taiga.io/) — Project management platform for startups and agile developers, free for Open Source
  * [Tara AI](https://tara.ai/) — Simple sprint management service. The free plan has unlimited tasks, sprints, and workspaces without user limits.
  * [targetprocess.com](https://www.targetprocess.com/) — Visual project management, from Kanban and Scrum to almost any operational process. Free for unlimited users, up to 1,000 data entities {[more details](https://www.targetprocess.com/pricing/)}
  * [taskade.com](https://www.taskade.com/) — Real-time collaborative task lists and team outlines. The free plan has one workspace with unlimited tasks and projects; 1GB file storage; 1-week project history; and five attendees per video meeting.
  * [taskulu.com](https://taskulu.com/) — Role based project management. Free up to 5 users. Integration with GitHub/Trello/Dropbox/Google Drive
  * [Teaminal](https://www.teaminal.com) - Standup, retro, and sprint planning tool for remote teams. Free for up to 15 users.
  * [teamwork.com](https://teamwork.com/) — Project management & Team Chat. Free for five users and two projects. Premium plans are available.
  * [teleretro.com](https://www.teleretro.com/) — Simple and fun retrospective tool with icebreakers, gifs and emojis. The free plan includes three retros and unlimited members.
  * [Tenzu](https://tenzu.net/) — Lightweight project management tool for agile teams. The SaaS relies on free contributions; users can always choose to give 0 and there is no features paywall {[more details](https://tenzu.net/pricing/)}
  * [testlio.com](https://testlio.com/) — Issue tracking, test management and beta testing platform. Free for private use
  * [terrastruct.com](https://terrastruct.com/) — Online diagram maker specifically for software architecture. Free tier up to 4 layers per diagram.
  * [todoist.com](https://todoist.com/) — Collaborative and individual task management. The free plan has: 5 active projects, five users in the project, file uploading up to 5MB, three filters, and one week of activity history.
  * [trello.com](https://trello.com/) — Board-based project management. Unlimited Personal Boards, 10 Team Boards.
  * [Tweek](https://tweek.so/) — Simple Weekly To-Do Calendar & Task Management.
  * [ubertesters.com](https://ubertesters.com/) — Test platform, integration and crowd testers, 2 projects, five members
  * [Wikifactory](https://wikifactory.com/) — Product designing Service with Projects, VCS & Issues. The free plan offers unlimited projects & collaborators and 3GB storage.
  * [Yodiz](https://www.yodiz.com/) — Agile development and issue tracking. Free up to 3 users, unlimited projects.
  * [YouTrack](https://www.jetbrains.com/youtrack/buy/#edition=incloud) — Free hosted YouTrack (InCloud) for FOSS projects and private projects (free for three users). Includes time tracking and agile boards
  * [zenhub.com](https://www.zenhub.com) — The only project management solution inside GitHub. Free for public repos, OSS, and nonprofit organizations
  * [zenkit.com](https://zenkit.com) — Project management and collaboration tool. Free for up to 5 members, 5 GB attachments.
  * [Zube](https://zube.io) — Project management with free plan for 4 Projects & 4 users. GitHub integration is available.
  * [Toggl](https://toggl.com/) — Provides two free productivity tools. [Toggl Track](https://toggl.com/track/) for time management and tracking app with a free plan provides seamless time tracking and reporting designed with freelancers in mind. It has unlimited tracking records, projects, clients, tags, reporting, and more. And [Toggl Plan](https://toggl.com/plan/) for task planning with a free plan for solo developers with unlimited tasks, milestones, and timelines.
  * [Sflow](https://sflow.io) — sflow.io is a project management tool built for agile software development, marketing, sales, and customer support, especially for outsourcing and cross-organization collaboration projects. Free plan up to 3 projects and five members.
  * [Pulse.red](https://pulse.red) — Free Minimalistic Time Tracker and Timesheet app for projects.

**[⬆️ Back to Top](#table-of-contents)**

## Storage and Media Processing

  * [AndroidFileHost](https://androidfilehost.com/) - Free file-sharing platform with unlimited speed, bandwidth, file count, download count, etc. It is mainly aimed for Android dev-related files like APK build, custom ROM & modifications, etc. But seems to accept any other files as well.
  * [borgbase.com](https://www.borgbase.com/) — Simple and secure offsite backup hosting for Borg Backup. 10 GB free backup space and two repositories.
  * [icedrive.net](https://www.icedrive.net/) - Simple cloud storage service. 10 GB free storage
  * [sync.com](https://www.sync.com/) - End-to-End cloud storage service. 5 GB of free storage
  * [pcloud.com](https://www.pcloud.com/) - Cloud storage service. Up to 10 GB of free storage
  * [sirv.com](https://sirv.com/) — Smart Image CDN with on-the-fly image optimization and resizing. The free tier includes 500 MB of storage and 2 GB of bandwidth.
  * [cloudimage.io](https://www.cloudimage.io/en/home) — Full image optimization and CDN service with 1500+ Points of Presence around the world. A variety of image resizing, compression, and watermarking functions. Open source plugins for responsive images, 360 image making and image editing. Free monthly plan with 25GB of CDN traffic 25GB of cache storage and unlimited transformations.
  * [cloudinary.com](https://cloudinary.com/) — Image upload, powerful manipulations, storage, and delivery for sites and apps, with Ruby, Python, Java, PHP, Objective-C, and more libraries. The free tier includes 25 monthly credits. One credit equals 1,000 image transformations, 1 GB of storage, or 1 GB of CDN usage.
  * [Dropshare](https://dropsha.re) - Zero-knowledge file sharing. End-to-end encrypted file sharing with AES-256-GCM encryption, client-side processing, and zero server-side data access. Free uploads for files up to 1GB with no data collection.
  * [embed.ly](https://embed.ly/) — Provides APIs for embedding media in a webpage, responsive image scaling, and extracting elements from a webpage. Free for up to 5,000 URLs/month at 15 requests/second
  * [filestack.com](https://www.filestack.com/) — File picker, transform, and deliver, free for 250 files, 500 transformations, and 3 GB bandwidth
  * [file.io](https://www.file.io) - 2 GB storage of files. A file is auto-deleted after one download. REST API to interact with the storage. Rate limit one request/minute.
  * [freetools.site](https://freetools.site/) — Free online tools. Convert or edit documents, images, audio, video, and more.
  * [GoFile.io](https://gofile.io/) - Free file sharing and storage platform can be used via web-based UI & also API. unlimited file size, bandwidth, download count, etc. But it will be deleted when a file becomes inactive (no download for more than ten days).
  * [gumlet.com](https://www.gumlet.com/) — Image and video hosting, processing and streaming via CDN. Provides generous free tier of 250 GB / month for videos and 30 GB  / month for images.
  * [image-charts.com](https://www.image-charts.com/) — Unlimited image chart generation with a watermark
  * [Imgbot](https://github.com/marketplace/imgbot) — Imgbot is a friendly robot that optimizes your images and saves you time. Optimized images mean smaller file sizes without sacrificing quality. It's free for open source.
  * [ImgBB](https://imgbb.com/) — ImgBB is an unlimited image hosting servce. Drag and drop your image anywhere on the screen. 32 MB / image limit. Receive Direct image links, BBCode and HTML thumbnails after uploading image. Login to see the upload history.
  * [imgen](https://www.jitbit.com/imgen/) - Free unlimited social cover image generation API, no watermark
  * [imgix](https://www.imgix.com/) - Image Caching, management and CDN. Free plan includes 1000 origin images, infinite transformations and 100 GB bandwidth
  * [kraken.io](https://kraken.io/) — Image optimization for website performance as a service, free plan up to 1 MB file size
  * [npoint.io](https://www.npoint.io/) — JSON store with collaborative schema editing
  * [nitropack.io](https://nitropack.io/) - Accelerate your site's speed on autopilot with complete front-end optimization (caching, images and code optimization, CDN). Free for up to 5,000 pageviews/month
  * [otixo.com](https://www.otixo.com/) — Encrypt, share, copy, and move all your cloud storage files from one place. The basic plan provides unlimited file transfer with 250 MB max. file size and allows five encrypted files
  * [packagecloud.io](https://packagecloud.io/) — Hosted Package Repositories for YUM, APT, RubyGem and PyPI.  Limited free plans and open-source plans are available via request
  * [getpantry.cloud](https://getpantry.cloud/) — A simple JSON data storage API perfect for personal projects, hackathons, and mobile apps!
  * [Pinata IPFS](https://pinata.cloud) — Pinata is the simplest way to upload and manage files on IPFS. Our friendly user interface and IPFS API make Pinata the easiest IPFS pinning service for platforms, creators, and collectors. 1 GB storage free, along with access to API.
  * [placekitten.com](https://placekitten.com/) — A quick and simple service for getting pictures of kittens for use as placeholders
  * [plot.ly](https://plot.ly/) — Graph and share your data. The free tier includes unlimited public files and ten private files
  * [podio.com](https://podio.com/) — You can use Podio with a team of up to five people and try out the features of the Basic Plan, except user management
  * [QRME.SH](https://qrme.sh) - Fast, beautiful bulk QR code generator – no login, no watermark, no ads. Up to 100 URLs per bulk export.
  * [QuickChart](https://quickchart.io) — Generate embeddable image charts, graphs, and QR codes
  * [redbooth.com](https://redbooth.com) — P2P file syncing, free for up to 2 users
  * [resmush.it](https://resmush.it) — reSmush.it is a FREE API that provides image optimization. reSmush.it has been implemented on the most common CMS such as WordPress, Drupal, or Magento. reSmush.it is the most used image optimization API with more than seven billion images already treated, and it is still Free of charge.
  * [Shotstack](https://shotstack.io) - API to generate and edit video at scale. Free up to 20 minutes of rendered video per month
  * [tinypng.com](https://tinypng.com/) — API to compress and resize PNG and JPEG images, offers 500 compressions for free each month
  * [transloadit.com](https://transloadit.com/) — Handles file uploads and encoding of video, audio, images, documents. Free for Open source, charities, and students via the GitHub Student Developer Pack. Commercial applications get 2 GB free for test driving
  * [twicpics.com](https://www.twicpics.com) - Responsive images as a service. It provides an image CDN, a media processing API, and a frontend library to automate image optimization. The service is free for up to 3GB of traffic/per month.
  * [uploadcare.com](https://uploadcare.com/hub/developers/) — Uploadcare provides the media pipeline  with the ultimate toolkit based on cutting-edge algorithms. All features are available for developers absolutely for free: File Uploading API and UI, Image CDN and Origin Services, Adaptive Delivery, and Smart Compression. The free tier has 3000 uploads, 3 GB traffic, and 3 GB storage.
  * [imagekit.io](https://imagekit.io) – Image CDN with automatic optimization, real-time transformation, and storage that you can integrate with existing setup in minutes. The free plan includes up to 20GB of bandwidth per month.
  * [internxt.com](https://internxt.com) – Internxt Drive is a zero-knowledge file storage service based on absolute privacy and uncompromising security. Sign up and get 10 GB for free, forever!
  * [degoo.com](https://degoo.com/) – AI based cloud storage with free up to 20 GB, three devices, 5 GB referral bonus (90 days account inactivity).
  * [MConverter.eu](https://mconverter.eu/) – Convert files in bulk. Supports many file formats, including new ones like [AVIF](https://mconverter.eu/convert/to/avif/). Extract all image frames from videos. Free for up to ten 100MB-files per day, processed in batches of two.
  * [ImageEngine](https://imageengine.io/) – ImageEngine is an easy to use global image CDN. Sub 60 sec setup. AVIF and JPEGXL support, WordPress-, Magento-, React-, Vue- plugins and more. Claim your free developer account [here](https://imageengine.io/developer-program/).
  * [DocsParse](https://docsparse.com/) – GPT powered AI processing of PDFs, Images, into structured data in JSON, CSV, EXCEL formats. 30 credits for free each month.
  * [VaocherApp QR Code Generator](https://www.vaocherapp.com/qr-code-generator) – Easily create custom QR codes for gift cards, gift vouchers, and promotions. Support custom styling, color, logo...
  * [LibreQR](https://libreqr.com) — Free QR code generator focused on privacy and no tracking. Free to use with no data collection.
  * [Doradrop](https://doradrop.com) — Doradrop is a file-sharing platform with unlimited storage and zero ads. Share files instantly through secure — no login needed.


**[⬆️ Back to Top](#table-of-contents)**

## Design and UI

  * [AllTheFreeStock](https://allthefreestock.com) - a curated list of free stock images, audio and videos.
  * [Float UI](https://floatui.com/) - free web development tool for quickly creating modern, responsive websites with sleek design, even for non-designers.
  * [Ant Design Landing Page](https://landing.ant.design/) - Ant Design Landing Page provides a template built by Ant Motion's motion components. It has a rich homepage template, downloads the template code package, and can be used quickly. You can also use the editor to quickly build your own dedicated page.
  * [Backlight](https://backlight.dev/) — With collaboration between developers and designers at heart, Backlight is a complete coding platform where teams build, document, publish, scale, and maintain Design Systems. The free plan allows up to 3 editors to work on one design system with unlimited viewers.
  * [BoxySVG](https://boxy-svg.com/app) — A free installable Web app for drawing SVGs and exporting in SVG, PNG, jpeg, and other formats.
  * [Carousel Hero](https://carouselhero.com/) - Free online tool to create social media carousels.
  * [Circum Icons](https://circumicons.com) - Consistent open-source icons such as SVG for React, Vue, and Svelte.
  * [clevebrush.com](https://www.cleverbrush.com/) — Free Graphics Design / Photo Collage App. Also, they offer paid integration of it as a component.
  * [cloudconvert.com](https://cloudconvert.com/) — Convert anything to anything. Two hundred eight supported formats including videos and gifs.
  * [CodeMyUI](https://codemyui.com) - Handpicked collection of Web Design & UI Inspiration with Code Snippets.
  * [ColorKit](https://colorkit.co/) - Create color palettes online or get inspiration from top palettes.
  * [coolors](https://coolors.co/) - Color palette generator. Free.
  * [CMYK Pantone](https://www.cmyktopantone.com/) - Easily convert CMYK values to the closest Pantone colors and other color models in seconds for free.
  * [Branition](https://branition.com/colors) - Hand-curated color pallets best fitted for brands.
  * [css-gradient.com](https://www.css-gradient.com/) - Free tool to quickly generate custom cross-browser CSS gradients. In RGB and HEX format.
  * [easyvectors.com](https://easyvectors.com/) — EasyVectors.com is a free SVG vector art stock. Download the best vector graphics absolutely for free.
  * [figma.com](https://www.figma.com) — Online, collaborative design tool for teams; free tier includes unlimited files and viewers with a max of 2 editors and three projects.
  * [Flyon UI](https://flyonui.com/)- The Easiest Components Library For Tailwind CSS.
  * [framer.com](https://www.framer.com/) - Framer helps you iterate and animate interface ideas for your next app, website, or product—starting with powerful layouts. For anyone validating Framer as a professional prototyping tool: unlimited viewers, up to 2 editors, and up to 3 projects.
  * [freeforcommercialuse.net](https://freeforcommercialuse.net/) — FFCU Worry-free model/property release stock photos
  * [Gradientos](https://www.gradientos.app) - Makes choosing a gradient fast and easy.
  * [Icon Horse](https://icon.horse) – Get the highest resolution favicon for any website from our simple API.
  * [Iconoir](https://iconoir.com) – An open-source icons library with thousands of icons, supporting React, React Native, Flutter, Vue, Figma, and Framer.
  * [Icons8](https://icons8.com) — Icons, illustrations, photos, music, and design tools. Free Plan offers Limited formats in lower resolution. Link to Icons8 when you use our assets.
  * [landen.co](https://www.landen.co) — Generate, edit, and publish beautiful websites and landing pages for your startup. All without code. The free tier allows you to have one website, fully customizable and published on the web.
  * [Quant Ux](https://quant-ux.com/) - Quant Ux is a prototyping and design tool. - It's completely free and also open source.
  * [lensdump.com](https://lensdump.com/) - Free cloud image hosting.
  * [Lorem Picsum](https://picsum.photos/) - A Free tool, easy to use, stylish placeholders. After our URL, add your desired image size (width & height), and you'll get a random image.
  * [LottieFiles](https://lottiefiles.com/) - The world’s largest online platform for the world’s most miniature animation format for designers, developers, and more. Access Lottie animation tools and plugins for Android, iOS, and Web.
  * [MagicPattern](https://www.magicpattern.design/tools) — A collection of CSS & SVG background generators & tools for gradients, patterns, and blobs.
  * [marvelapp.com](https://marvelapp.com/) — Design, prototyping, and collaboration, free plan limited to one user and project.
  * [Mindmup.com](https://www.mindmup.com/) — Unlimited mind maps for free and store them in the cloud. Your mind maps are available everywhere, instantly, from any device.
  * [Mockplus iDoc](https://www.mockplus.com/idoc) - Mockplus iDoc is a powerful design collaboration & handoff tool. Free Plan includes three users and five projects with all features available.
  * [mockupmark.com](https://mockupmark.com/create/free) — Create realistic t-shirt and clothing mockups for social media and E-commerce, 40 free mockups.
  * [Modeldraw.com](https://modeldraw.com) — Complete diagramming platform with UML, system architecture, flowcharts, mind maps, and Agile workflows. Real-time collaboration with unlimited team members, no credit card required.
  * [Mossaik](https://mossaik.app) - Free SVG image generator with different tools like waves, blogs and patterns.
  * [movingpencils.com](https://movingpencils.com) — Fast, browser-based vector editor. Completely free.
  * [Octopus.do](https://octopus.do) — Visual sitemap builder. Build your website structure in real time and rapidly share it to collaborate with your team or clients.
  * [Pencil](https://github.com/evolus/pencil) - Open source design tool using Electron.
  * [Penpot](https://penpot.app) - Web-based, open-source design and prototyping tool. Supports SVG. Completely free.
  * [pexels.com](https://www.pexels.com/) - Free stock photos for commercial use. Has a free API that allows you to search photos by keywords.
  * [photopea.com](https://www.photopea.com) — A Free, Advanced online design editor with Adobe Photoshop UI supporting PSD, XCF & Sketch formats (Adobe Photoshop, Gimp and Sketch App).
  * [pixlr.com](https://pixlr.com/) — Free online browser editor on the level of commercial ones.
  * [Plasmic](https://www.plasmic.app/) - A fast, easy-to-use, robust web design tool and page builder that integrates into your codebase. Build responsive pages or complex components; optionally extend with code; and publish to production sites and apps.
  * [Pravatar](https://pravatar.cc/) - Generate a random/placeholder fake avatar whose URL can be directly hot-linked in your web/app.
  * [PNG to WebP Converter](https://pngtowebpconverter.com/) - Convert PNG images to WebP images directly in your browser. No upload required, fully client-side processing for maximum privacy and security.
  * [Proto.io](https://www.proto.io) - Create fully interactive UI prototypes without coding. The free tier is available when the free trial ends. The free tier includes one user, one project, five prototypes, 100MB of online storage, and a preview of the proto.io app.
  * [resizeappicon.com](https://resizeappicon.com/) — A simple service to resize and manage your app icons.
  * [Rive](https://rive.app) — Create and ship beautiful animations to any platform. Free forever for Individuals. The service is an editor that also hosts all the graphics on their servers. They also provide runtimes for many platforms to run representations made using Rive.
  * [storyset.com](https://storyset.com/) — Create incredible free customized illustrations for your project using this tool.
  * [smartmockups.com](https://smartmockups.com/) — Create product mockups, 200 free mockups.
  * [Shadcn Studio](https://shadcnstudio.com/theme-editor) — Preview your theme changes across different components and layouts.
  * [Tailark](https://tailark.com/) - A collection of modern, responsive, pre-built UI blocks designed for marketing websites.
  * [tabler-icons.io](https://tabler-icons.io/) — Over 1500 free copy-and-paste SVG editable icons.
  * [tweakcn](https://tweakcn.com/) — Beautiful themes for shadcn/ui. Customize colors, typography, and more in real-time.
  * [UI Avatars](https://ui-avatars.com/) - Generate avatars with initials from names. The URLs can be directly hot-linked in your web/app. Support config parameters via the URL.
  * [unDraw](https://undraw.co/) - A constantly updated collection of beautiful SVG images that you can use completely free without attribution.
  * [unsplash.com](https://unsplash.com/) - Free stock photos for commercial and noncommercial purposes (do-whatever-you-want license).
  * [vectr.com](https://vectr.com/) — Free Design App for Web + Desktop.
  * [walkme.com](https://www.walkme.com/) — Enterprise Class Guidance and Engagement Platform, free plan three walk-thru up to 5 steps/walk.
  * [Webflow](https://webflow.com) - WYSIWYG website builder with animations and website hosting. Free for two projects.
  * [Updrafts.app](https://updrafts.app) - WYSIWYG website builder for tailwindcss-based designs. Free for non-commercial usage.
  * [whimsical.com](https://whimsical.com/) - Collaborative flowcharts, wireframes, sticky notes and mind maps. Create up to 4 free boards.
  * [Zeplin](https://zeplin.io/) — Designer and developer collaboration platform. Show designs, assets, and style guides. Free for one project.
  * [Pixelixe](https://pixelixe.com/) — Create and edit engaging, unique graphics and images online.
  * [Responsively App](https://responsively.app) - A free dev tool for faster and more precise responsive web application development.
  * [SceneLab](https://scenelab.io) - Online mockup graphics editor with an ever-expanding collection of free design templates
  * [xLayers](https://xlayers.dev) - Preview and convert Sketch design files into Angular, React, Vue, LitElement, Stencil, Xamarin, and more (free and open source at https://github.com/xlayers/xlayers)
  * [Grapedrop](https://grapedrop.com/) — Responsive, powerful, SEO-optimized web page builder based on GrapesJS Framework. Free for the first five pages, unlimited custom domains, all features, and simple usage.
  * [Mastershot](https://mastershot.app) - Completely free browser-based video editor. No watermark, up to 1080p export options.
  * [Unicorn Platform](https://unicornplatform.com/) - Effortless landing page builder with hosting. One website for free.
  * [SVGmix.com](https://www.svgmix.com/) - Massive repository of 300K+ of free SVG icons, collections, and brand logos. It has a simple vector editing program right in the browser for quick file editing.
  * [svgrepo.com](https://www.svgrepo.com/) - Explore, search, and find the best-fitting icons or vectors for your projects using various vector libraries. Download free SVG Vectors for commercial use.
  * [haikei.app](https://www.haikei.app/) - Haikei is a web app to generate unique SVG shapes, backgrounds, and patterns – ready to use with your design tools and workflow.
  * [Canva](https://canva.com) - Free online design tool to create visual content.
  * [Superdesigner](https://superdesigner.co) - A collection of free design tools to create unique backgrounds, patterns, shapes, images, and more with just a few clicks.
  * [TeleportHQ](https://teleporthq.io/) - Low-code Front-end Design & Development Platform. TeleportHQ is the collaborative front-end platform to instantly create and publish headless static websites. Three free projects, unlimited collaborators, and free code export.
  * [vector.express](https://vector.express) — Convert your AI, CDR, DWG, DXF, EPS, HPGL, PDF, PLT, PS and SVG vector fast and easily.
  * [Vertopal](https://www.vertopal.com) - Vertopal is a free online platform for converting files to various formats. Including developer converters like JPG to SVG, GIF to APNG, PNG to WEBP, JSON to XML, etc.
  * [okso.app](https://okso.app) - Minimalistic online drawing app. Allows to create fast sketches and visual notes. Exports sketches to PNG, JPG, SVG, and WEBP. Also installable as PWA. Free to use for everyone (no registration is needed).
  * [Wdrfree SVG](https://wdrfree.com/free-svg) - Black and White Free SVG Cut files.
  * [Lucide](https://lucide.dev) - Free customizable and consistent SVG icon toolkit.
  * [Logo.dev](https://www.logo.dev) - Company logo API with 44M+ brands that's as easy as calling a URL. First 10,000 API calls are free.
  * [MDBootstrap](https://mdbootstrap.com/) - Free for personal & commercial use Bootstrap, Angular, React, and Vue UI Kits with over 700 components, stunning templates, 1-min installation, extensive tutorials & colossal community.
  * [TW Elements](https://tw-elements.com/) - Free Bootstrap components recreated with Tailwind CSS, but with better design and more functionalities.
  * [DaisyUI](https://daisyui.com/) -- Free. "Use Tailwind CSS but write fewer class names" offers components like buttons.
  * [Scrollbar.app](https://scrollbar.app) -- Simple free web app for designing custom scrollbars for the web.
  * [css.glass](https://css.glass/) -- Free web app for creating glassmorphic designs using CSS.
  * [hypercolor.dev](https://hypercolor.dev/) -- A curated collection of Tailwind CSS color gradients also provides a variety of generators to create your own.
  * [iconify.design](https://icon-sets.iconify.design/) -- A collection of over 100 icon packs with a unified interface. Allows you to search for icons across packs and export individual icons as SVGs or for popular web frameworks.
  * [NextUI](https://nextui.org/) -- Free. Beautiful, fast, and modern React & Next.js UI library.
  * [Glyphs](https://glyphs.fyi/) -- Free, The Mightiest Icons on the Web, Fully editable & truly open source design system.
  * [ShadcnUI](https://ui.shadcn.com/) -- Beautifully designed components that you can copy and paste into your apps. Accessible. Customizable. Open Source.
  * [HyperUI](https://www.hyperui.dev/) -- Free Open Source Tailwind CSS Components.
  * [Calendar Icons Generator](https://calendariconsgenerator.app/) -- Generate an entire year's worth of unique icons in a single click, absolutely FREE
  * [Image BG Blurer](https://imagebgblurer.com/) -- Generate a blurred background frame for an image, using that image source as the background blur, for Notion, Trello, Jira, and more tools
  * [Webstudio](https://webstudio.is/) -- Open-source alternative to Webflow. The free plan offers unlimited websites on their domain. Five websites with custom domains. Ten thousand page views/month. 2 GB asset storage.
  * [Nappy](https://nappy.co/) -- Beautiful photos of Black and Brown people, for free. For commercial and personal use.
  * [Tailkits](https://tailkits.com/) -- A curated collection of Tailwind templates, components, and tools, plus useful generators for code, grids, box shadows, and more.
  * [Tailcolors](https://tailcolors.com/) -- A beautiful Tailwind CSS v4 color palette. Instantly preview & copy the perfect Tailwind CSS color class.
  * [Excalidraw](https://excalidraw.com/) -- A free online drawing document web page with free save to local and export support.
  * [Lunacy](https://icons8.com/lunacy) -- Free graphic design tool with offline support, built-in assets (icons, photos, illustrations), and real-time collaboration. The free tier includes 10 cloud documents, a 30-day history, low-res assets, and basic design tools.
  * [Flows](https://flows.sh/) -- A fully customizable product adoption platform for building onboarding and user engagement experiences. Free for up to 250 monthly tracked users.

**[⬆️ Back to Top](#table-of-contents)**

## Design Inspiration

  * [awwwards.](https://www.awwwards.com/) - [Top websites] A showcase of all the best-designed websites (voted on by designers).
  * [Behance](https://www.behance.net/) - [Design showcase] A place where designers showcase their work. Filterable with categories for UI/UX projects.
  * [dribbble](https://dribbble.com/) - [Design showcase] Unique design inspiration, generally not from real applications.
  * [Landings](https://landings.dev/) - [Web screenshots] Find the best landing pages for your design inspiration based on your preference.
  * [Lapa Ninja](https://www.lapa.ninja/) - [Landing page / UI KIts / Web screenshots] Lapa Ninja is a gallery featuring the best 6025 landing page examples, free books for designers and free UI kits from around the web.
  * [LovelyLanding.net](https://www.lovelylanding.net/) - [Landing Page Designs] Frequently updated landing page screenshots. Includes Desktop, Tablet, and Mobile screenshots.
  * [Mobbin](https://mobbin.design/) - [Mobile screenshots] Save hours of UI & UX research with our library of 50,000+ fully searchable mobile app screenshots.
  * [Uiland Design](https://uiland.design/) - [Mobile screenshots] Explore Mobile and Web UI Designs from Leading Companies in Africa and the world.
  * [Mobile Patterns](https://www.mobile-patterns.com/) - [Mobile screenshots] A design inspirational library featuring the finest UI UX Patterns (iOS and Android) for designers, developers, and product makers to reference.
  * [Page Flows](https://pageflows.com/) - [Mobile / web videos and screenshots] Videos of full flows across many mobile and web apps. Also includes screenshots. Highly searchable and indexed.
  * [Screenlane](https://screenlane.com/) - [Mobile screenshots] Get inspired and keep up with the latest web & mobile app UI design trends. Filterable by pattern and app.
  * [scrnshts](https://scrnshts.club/) - [Mobile screenshots] A hand-picked collection of the finest app store design screenshots.
  * [Refero](https://refero.design/) - [Web screenshots] Tagged and searchable collection of design references from great web applications.


**[⬆️ Back to Top](#table-of-contents)**

## Data Visualization on Maps

  * [IP Geolocation](https://ipgeolocation.io/) — Free DEVELOPER plan available with 30K requests/month.
  * [carto.com](https://carto.com/) — Create maps and geospatial APIs from your and public data.
  * [Clockwork Micro](https://clockworkmicro.com/) — Map tools that work like clockwork. Fifty thousand free monthly queries (map tiles, db2vector, elevation).
  * [developers.arcgis.com](https://developers.arcgis.com) — APIs and SDKs for maps, geospatial data storage, analysis, geocoding, routing, and more across web, desktop, and mobile. Two million free base map tiles, 20,000 non-stored geocodes, 20,000 simple routes, 5,000 drive time calculations, and 5GB free tile+data storage per month.
  * [Foursquare](https://developer.foursquare.com/) - Location discovery, venue search, and context-aware content from Places API and Pilgrim SDK.
  * [geoapify.com](https://www.geoapify.com/) - Vector and raster map tiles, geocoding, places, routing, isolines APIs. Three thousand free requests/day.
  * [geocod.io](https://www.geocod.io/) — Geocoding via API or CSV Upload. Two thousand five hundred free queries/day.
  * [geocodify.com](https://geocodify.com/) — Geocoding and Geoparsing via API or CSV Upload. 10k free queries/month.
  * [geojs.io](https://www.geojs.io/) - Highly available REST/JSON/JSONP IP Geolocation lookup API.
  * [giscloud.com](https://www.giscloud.com/) — Visualize, analyze, and share geo data online.
  * [graphhopper.com](https://www.graphhopper.com/) A free developer package is offered for Routing, Route Optimization, Distance Matrix, Geocoding, and Map Matching.
  * [here](https://developer.here.com/) — APIs and SDKs for maps and location-aware apps. 250k transactions/month for free.
  * [locationiq.com](https://locationiq.com/) — Geocoding, Maps, and Routing APIs. Five thousand requests/day for free.
  * [mapbox.com](https://www.mapbox.com/) — Maps, geospatial services and SDKs for displaying map data.
  * [maptiler.com](https://www.maptiler.com/cloud/) — Vector maps, map services and SDKs for map visualization. Free vector tiles with weekly updates and four map styles.
  * [nominatim.org](https://nominatim.org/) — OpenStreetMap's free geocoding service, providing global address search functionality and reverse geocoding capabilities.
  * [nextbillion.ai](https://nextbillion.ai/) - Maps related services: Geocoding, Navigation (Direction, Routing, Route Optimization, Distance Matrix), Maps SDK (Vector, Static, Mobile SDK). [Free with specified quota](https://nextbillion.ai/pricing) for each services.
  * [opencagedata.com](https://opencagedata.com) — Geocoding API aggregating OpenStreetMap and other open geo sources. Two thousand five hundred free queries/day.
  * [osmnames](https://osmnames.org/) — Geocoding, search results ranked by the popularity of related Wikipedia page.
  * [positionstack](https://positionstack.com/) - Free geocoding for global places and coordinates. 25,000 Requests per month for personal use.
  * [stadiamaps.com](https://stadiamaps.com/) — Map tiles, routing, navigation, and other geospatial APIs. Two thousand five hundred free map views and API requests/day for non-commercial usage and testing.
  * [maps.stamen.com](http://maps.stamen.com/) - Free map tiles and tile hosting.
  * [ipstack](https://ipstack.com/) - Locate and identify Website Visitors by IP Address
  * [Geokeo api](https://geokeo.com) - Geocoding API with language correction and more. Worldwide coverage. 2,500 free daily queries

**[⬆️ Back to Top](#table-of-contents)**

## Package Build System

  * [build.opensuse.org](https://build.opensuse.org/) — Package build service for multiple distros (SUSE, EL, Fedora, Debian, etc.).
  * [copr.fedorainfracloud.org](https://copr.fedorainfracloud.org) — Mock-based RPM build service for Fedora and EL.
  * [help.launchpad.net](https://help.launchpad.net/Packaging) — Ubuntu and Debian build service.

**[⬆️ Back to Top](#table-of-contents)**

## IDE and Code Editing

  * [3v4l](https://3v4l.org/) - Free online PHP shell and snippet-sharing site, that runs your code in 300+ PHP versions
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
  * [Code::Blocks](https://codeblocks.org) — Free Fortran & C/C++ IDE. Open Source and runs on Windows,macOS & Linux.
  * [Cody](https://sourcegraph.com/cody) - Free AI coding assistant that can write (Code blocks, autocomplete, unit tests), understand (knowledge of your entire codebase), fix, and find your code. Available for VS Code, JetBrains and Online.
  * [codiga.io](https://codiga.io/) — Coding Assistant that lets you search, define, and reuse code snippets directly in your IDE. Free for individual and small organizations.
  * [codesnip.com.br](https://codesnip.com.br) — Simple code snippets manager with categories, search and tags. free and unlimited.
  * [cocalc.com](https://cocalc.com/) — (formerly SageMathCloud at cloud.sagemath.com) — Collaborative calculation in the cloud. Browser access to full Ubuntu with built-in collaboration and lots of free software for mathematics, science, data science, preinstalled: Python, LaTeX, Jupyter Notebooks, SageMath, scikitlearn, etc.
  * [code.cs50.io](https://code.cs50.io/) - Visual Studio Code for CS50 is a web app at code.cs50.io that adapts GitHub Codespaces for students and teachers.
  * [codepen.io](https://codepen.io/) — CodePen is a playground for the front-end side of the web.
  * [codesandbox.io](https://codesandbox.io/) — Online Playground for React, Vue, Angular, Preact, and more.
  * [Components.studio](https://webcomponents.dev/) - Code components in isolation, visualize them in stories, test them, and publish them on npm.
  * [Eclipse Che](https://www.eclipse.org/che/) - Web-based and Kubernetes-Native IDE for Developer Teams with multi-language support. Open Source and community-driven. An online instance hosted by Red Hat is available at [workspaces.openshift.com](https://workspaces.openshift.com/).
  * [fakejson.com](https://fakejson.com/) — FakeJSON helps you quickly generate fake data using its API. Make an API request describing what you want and how you want it. The API returns it all in JSON. Speed up the go-to-market process for ideas and fake it till you make it.
  * [ForgeCode](https://forgecode.dev/) — AI-enabled pair programmer for Claude, GPT4 Series, Grok, Deepseek, Gemini and all frontier models. Works natively with your CLI and integrates seamlessly with any IDE. Free tier includes basic AI model access with local processing.
  * [GetVM](https://getvm.io) — Instant free Linux and IDEs chrome sidebar. The free tier includes 5 VMs per day.
  * [ide.goorm.io](https://ide.goorm.io) goormIDE is full IDE on cloud. multi-language support, Linux-based container via the fully-featured web-based terminal, port forwarding, custom URL, real-time collaboration and chat, share link, Git/Subversion support. There are many more features (The free tier includes 1GB RAM and 10GB Storage per container, 5 Container slots).
  * [JDoodle](https://www.jdoodle.com) — Online compiler and editor for more than 60 programming languages with a free plan for REST API code compiling up to 200 credits per day.
  * [jetbrains.com](https://jetbrains.com/products.html) — Productivity tools, IDEs and deploy tools (aka [IntelliJ IDEA](https://www.jetbrains.com/idea/), [PyCharm](https://www.jetbrains.com/pycharm/), etc). Free license for students, teachers, Open Source and user groups.
  * [jsbin.com](https://jsbin.com) — JS Bin is another playground and code-sharing site of front-end web (HTML, CSS, and JavaScript. It Also supports Markdown, Jade, and Sass).
  * [jsfiddle.net](https://jsfiddle.net/) — JS Fiddle is a playground and code-sharing site of front-end web, supporting collaboration.
  * [JSONPlaceholder](https://jsonplaceholder.typicode.com/) Some REST API endpoints that return some fake data in JSON format. The source code is also available if you would like to run the server locally.
  * [Lazarus](https://www.lazarus-ide.org/) — Lazarus is a Delphi-compatible cross-platform IDE for Rapid Application Development.
  * [MarsCode](https://www.marscode.com/) - A free AI-powered cloud-based IDE.
  * [micro-jaymock](https://micro-jaymock.now.sh/) - Tiny API mocking microservice for generating fake JSON data.
  * [mockable.io](https://www.mockable.io/) — Mockable is a simple configurable service to mock out RESTful API or SOAP web services. This online service allows you to quickly define REST API or SOAP endpoints and have them return JSON or XML data.
  * [mockaroo](https://mockaroo.com/) — Mockaroo lets you generate realistic test data in CSV, JSON, SQL, and Excel formats. You can also create mocks for back-end API.
  * [Mocklets](https://mocklets.com) - an HTTP-based mock API simulator that helps simulate APIs for faster parallel development and more comprehensive testing, with a lifetime free tier.
  * [Paiza](https://paiza.cloud/en/) — Develop Web apps in Browser without needing to set up anything. Free Plan offers one server with 24 24-hour lifetime and 4 hours of running time per day with 2 CPU cores, 2 GB RAM, and 1 GB storage.
  * [Prepros](https://prepros.io/) - Prepros can compile Sass, Less, Stylus, Pug/Jade, Haml, Slim, CoffeeScript, and TypeScript out of the box, reloads your browsers and makes it easy to develop & test your websites so you can focus on making them perfect. You can also add your own tools with just a few clicks.
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
  * [PHPSandbox](https://phpsandbox.io/) — Online development environment for PHP
  * [WebDB](https://webdb.app) - Free Efficient Database IDE. Featuring Server Discovery, ERD, Data Generator, AI, NoSQL Structure Manager, Database Versioning and many more.
  * [Zed](https://zed.dev/) - Zed is a high-performance, multiplayer code editor from the creators of Atom and Tree-sitter.
  * [OneCompiler](https://onecompiler.com/) - Free online compiler supporting 70+ languages including Java, Python, C++, JavaScript.


**[⬆️ Back to Top](#table-of-contents)**

## Analytics, Events and Statistics

  * [Userbird](https://userbird.com) - Google Analytics alternative with heatmaps, session recordings and revenue tracking.
  * [Repohistory](https://repohistory.com) - Beautiful dashboard for tracking GitHub repo traffic history longer than 14 days. Free Plan allows users to monitor traffic for a single repository.
  * [Dwh.dev](https://dwh.dev) - Data Cloud Observability Solution (Snowflake). Free for personal use.
  * [Hightouch](https://hightouch.com/) - Hightouch is a Reverse ETL platform that helps you sync customer data from your data warehouse to your CRM, marketing, and support tools. The free tier offers you one destination to sync data to.
  * [Avo](https://avo.app/) — Simplified analytics release workflow. Single-source-of-truth tracking plan, type-safe analytics tracking library, in-app debuggers, and data observability to catch all data issues before you release. Free for two workspace members and 1 hour data observability lookback.
  * [Branch](https://www.branch.io) — Mobile Analytics Platform. Free Tier offers up to 10K Mobile App Users with deep-linking & other services.
  * [Census](https://www.getcensus.com/) — Reverse ETL & Operational Analytics Platform. Sync 10 fields from your data warehouse to 60+ SaaS like Salesforce, Zendesk, or Amplitude.
  * [Clicky](https://clicky.com) — Website Analytics Platform. Free Plan for one website with 3000 views analytics.
  * [Databox](https://databox.com) — Business Insights & Analytics by combining other analytics & BI platforms. Free Plan offers 3 users, dashboards & data sources. 11M historical data records.
  * [Hitsteps.com](https://hitsteps.com/) — 2,000 pageviews per month for 1 website
  * [amplitude.com](https://amplitude.com/) — 1 million monthly events, up to 2 apps
  * [GoatCounter](https://www.goatcounter.com/) — GoatCounter is an open-source web analytics platform available as a hosted service (free for non-commercial use) or self-hosted app. It aims to offer easy-to-use and meaningful privacy-friendly web analytics as an alternative to Google Analytics or Matomo. The free tier is for non-commercial use and includes unlimited sites, six months of data retention, and 100k pageviews/month.
  * [Google Analytics](https://analytics.google.com/) — Google Analytics
  * [MetricsWave](https://metricswave.com) — Privacy-friendly Google Analytics alternative for developers. Free plan allows 1M pageviews per month without credit card required.
  * [Expensify](https://www.expensify.com/) — Expense reporting, free personal reporting approval workflow
  * [getinsights.io](https://getinsights.io) - Privacy-focused, cookie-free analytics, free for up to 3k events/month.
  * [heap.io](https://heap.io) — Automatically captures every user action in iOS or web apps. Free for up to 10K monthly sessions.
  * [Hotjar](https://hotjar.com) — Website Analytics and Reports . Free Plan allows 2000 pageviews/day. One hundred snapshots/day (max capacity: 300). Three snapshot heatmaps can be stored for 365 days. Unlimited Team Members. Also in App and standalone surveys, feedback widgets with screenshots. Free tier allows creating 3 surveys & 3 feedback widgets and collecting 20 responses per month.
  * [Keen](https://keen.io/) — Custom Analytics for data collection, analysis and visualization. 1,000 events/month free
  * [Yandex.Datalens](https://datalens.yandex.com/) — Yandex Cloud data visualization and analysis service. The service is provided free of charge. No restrictions on the number of users and requests.
  * [Yandex.Metrica](https://metrica.yandex.com/) — Unlimited free analytics
  * [Mixpanel](https://mixpanel.com/) — 100,000 monthly tracked users, unlimited data history and seats, US or EU data residency
  * [Moesif](https://www.moesif.com) — API analytics for REST and GraphQL. (Free up to 500,000 API calls/mo)
  * [optimizely.com](https://www.optimizely.com) — A/B Testing solution, free starter plan, one website, 1 iOS, and 1 Android app
  * [Microsoft PowerBI](https://powerbi.com) — Business Insights & Analytics by Microsoft. Free Plan offers limited use with 1 Million User licenses.
  * [Row Zero](https://rowzero.io) - Blazingly fast, connected spreadsheet. Connect directly to data databases, S3, and APIs. Import, analyze, graph, and share millions of rows instantly. Three free (forever) workbooks.
  * [sematext.com](https://sematext.com/cloud/) — Free for up to 50 K actions/month, 1-day data retention, unlimited dashboards, users, etc.
  * [Similar Web](https://similarweb.com) — Analytics for Web & Mobile Apps. Free Plan offers five results per metric, one month of mobile app data & 3 months of website data.
  * [StatCounter](https://statcounter.com/) — Website Viewer Analytics. Free plan for analytics of 500 most recent visitors.
  * [Statsig](https://statsig.com) - All-in-one platform spanning across analytics, feature flagging, and A/B testing. Free for up to 1m metered events per month.
  * [Tableau Developer Program](https://www.tableau.com/developer) — Innovate, create, and make Tableau work perfectly for your organization. The free developer program gives a personal development sandbox license for Tableau Online. The version is the latest pre-release version so Data Devs can test each & every feature of this superb platform.
  * [usabilityhub.com](https://usabilityhub.com/) — Test designs and mockups on real people and track visitors. Free for one user, unlimited tests
  * [woopra.com](https://www.woopra.com/) — Free user analytics platform for 500K actions, 90-day data retention, 30+ one-click integration.
  * [counter.dev](https://counter.dev) — Web analytics made simple and therefore privacy friendly. Free or pay what you want by donation.
  * [PostHog](https://posthog.com) - Full Product Analytics suite free for up to 1m tracked events per month. Also provides unlinited in-App Surveys with 250/month responses.
  * [Uptrace](https://uptrace.dev) - Distributed Tracing Tool that helps developers pinpoint failures and find performance bottlenecks. Has a free plan, offers a complimentary Personal subscription for open-source projects, and has an open-source version.
  * [Microsoft Clarity](https://clarity.microsoft.com/) - Clarity is a free, easy-to-use tool that captures how real people use your site.
  * [Beampipe.io](https://beampipe.io) - Beampipe is simple, privacy-focussed web analytics. free for up to 5 domains & 10k monthly page views.
  * [Aptabase](https://aptabase.com) — Open Source, Privacy-Friendly, and Simple Analytics for Mobile and Desktop Apps. SDKs for Swift, Kotlin, React Native, Flutter, Electron, and many others. Free for up to 20,000 events per month.
  * [Trackingplan](https://www.trackingplan.com/) - Automatically detect digital analytics, marketing data and pixels issues, maintain up-to-date tracking plans, and foster seamless collaboration. Deploy it to your production environment with real traffic or add analytics coverage to your regression tests without writing code.
  * [LogSpot](https://logspot.io) - Full unified web and product analytics platform, including embeddable analytics widgets and automated robots (slack, telegram, and webhooks). Free plan includes 10,000 events per month.
  * [Umami](https://umami.is/) - Simple, fast, privacy-focused, open-source alternative to Google Analytics.
  * [TrackWith Dicloud](https://dicloud.net/trackwith-privacy-focused-analytics/) - Free lightweight privacy-focused alternative to Google Analytics. Unlimited pageviews, unlimited visitor, unlimited page heatmaps & goal tracking. Free for up to 3 domains and 600 session replay per domain.
  * [AppFit](https://appfit.io) - AppFit is a comprehensive analytics and product management tool designed to facilitate seamless, cross-platform management of analytics and product updates. Free plan includes 10,000 events per month, product journal and weekly insights.
  * [Seline](https://seline.so) - Seline is a simple & private website and product analytics. Cookieless, lightweight, independent. Free plan includes 3,000 events per month and provides access to all our features, such as the dashboard, user journeys, funnels, and more.
  * [Peasy](https://peasy.so) - Peasy is a lightweight, privacy-focused analytics tool for websites and products. Free plan includes 3,000 events per month.
  * [Rybbit](https://rybbit.io) - Open-source and cookieless alternative to Google Analytics that is 10x more intuitive. Free plans has 3,000 monthly events. 

**[⬆️ Back to Top](#table-of-contents)**

## Visitor Session Recording

  * [Reactflow.com](https://www.reactflow.com/) — Per site: 1,000 pages views/day, three heatmaps, three widgets, free bug tracking
  * [OpenReplay.com](https://www.openreplay.com) - Open-source session replay with dev tools for bug reproduction, live session for real-time support, and product analytics suite. One thousand sessions/month with access to all features and 7-day retention.
  * [LogRocket.com](https://www.logrocket.com) - 1,000 sessions/month with 30-day retention, error tracking, live mode
  * [FullStory.com](https://www.fullstory.com) — 1,000 sessions/month with one month data retention and three user seats. More information [here](https://help.fullstory.com/hc/en-us/articles/360020623354-FullStory-Free-Edition).
  * [hotjar.com](https://www.hotjar.com/) — Per site: 1,050 pages views/month, unlimited heatmaps, data stored for three months
  * [inspectlet.com](https://www.inspectlet.com/) — 2,500 sessions/month free for one website
  * [Microsoft Clarity](https://clarity.microsoft.com/) - Session recording completely free with "no traffic limits", no project limits, and no sampling
  * [mouseflow.com](https://mouseflow.com/) — 500 sessions/month free for one website
  * [mousestats.com](https://www.mousestats.com/) — 100 sessions/month free for one website
  * [smartlook.com](https://www.smartlook.com/) — free packages for web and mobile apps (1500 sessions/month), three heatmaps, one funnel, 1-month data history
  * [howuku.com](https://howuku.com) — Track user interaction, engagement, and event. Free for up to 5,000 visits/month
  * [UXtweak.com](https://www.uxtweak.com/) — Record and watch how visitors use your website or app. Free unlimited time for small projects

**[⬆️ Back to Top](#table-of-contents)**

## International Mobile Number Verification API and SDK

  * [numverify](https://numverify.com/) — Global phone number validation and lookup JSON API. 100 API requests/month
  * [veriphone](https://veriphone.io/) — Global phone number verification in a free, fast, reliable JSON API. 1000 requests/month

**[⬆️ Back to Top](#table-of-contents)**

## Payment and Billing Integration

  * [Qonversion](http://qonversion.io/) - All-in-one cross-platform subscription management platform offering analytics, A/B testing, Apple Search Ads, remote configs, and growth tools for optimizing in-app purchases and monetization. Compatible with iOS, Android, React Native, Flutter, Unity, Cordova, Stripe, and web. Free up to $10k in monthly tracked revenue.
  * [ParityVend](https://www.ambeteco.com/ParityVend/) – Automatically adjust pricing based on visitor location to expand your business globally and reach new markets (purchasing power parity). The free plan includes 7,500 API requests/month.
  * [Adapty.io](https://adapty.io/) – One-stop solution with open-source SDK for mobile in-app subscription integration to iOS, Android, React Native, Flutter, Unity, or web app. Free up to $10k monthly revenue.
  * [CoinMarketCap](https://coinmarketcap.com/api/) — Provides cryptocurrency market data including the latest crypto and fiat currency exchange rates. The free tier offers 10K call credits/month.
  * [CurrencyFreaks](https://currencyfreaks.com/) — Provides current and historical currency exchange rates. Free DEVELOPER plan available with 1000 requests/month.
  * [CoinGecko](https://www.coingecko.com/en/api) — Provides cryptocurrency market data including the latest crypto exchange rates and historical data. The demo api comes with a stable rate limit of 30 calls/min and a monthly cap of 10,000 calls.
  * [CurrencyApi](https://currencyapi.net/) — Live Currency Rates for Physical and Cryptocurrencies, delivered in JSON and XML. The free tier offers 1,250 API requests/month.
  * [currencylayer](https://currencylayer.com/) — Reliable Exchange Rates and Currency Conversion for your Business, 100 API requests/month free.
  * [exchangerate-api.com](https://www.exchangerate-api.com) - An easy-to-use currency conversion JSON API. The free tier updates once per day with a limit of 1,500 requests/month.
  * [FraudLabsPRO](https://www.fraudlabspro.com) — Help merchants to prevent payment fraud and chargebacks. Free Micro Plan available with 500 queries/month.
  * [FxRatesAPI](https://fxratesapi.com) — Provides real-time and historical exchange rates. The free tier requires attribution.
  * [Moesif API Monetization](https://www.moesif.com/) - Generate revenue from APIs via usage-based billing. Connect to Stripe, Chargebee, etc. The free tier offers 30,000 events/month.
  * [Nami ML](https://www.namiml.com/) - Complete platform for in-app purchases and subscriptions on iOS and Android, including no-code paywalls, CRM, and analytics.  Free for all base features to run an IAP business.
  * [RevenueCat](https://www.revenuecat.com/) — Hosted backend for in-app purchases and subscriptions (iOS and Android). Free up to $2.5k/mo in tracked revenue.
  * [vatlayer](https://vatlayer.com/) — Instant VAT number validation and EU VAT rates API, free 100 API requests/month
  * [Currencyapi](https://currencyapi.com) — Free currency conversion and exchange rate data API. Free 300 requests per month, 10 requests per minute for private use.

**[⬆️ Back to Top](#table-of-contents)**

## Docker Related

  * [canister.io](https://canister.io/) — 20 free private repositories for developers, 30 free private repositories for teams to build and store Docker images
  * [Container Registry Service](https://container-registry.com/) - Harbor based Container Management Solution. The free tier offers 1 GB of storage for private repositories.
  * [Docker Hub](https://hub.docker.com) — One free private repository and unlimited public repositories to build and store Docker images
  * [Play with Docker](https://labs.play-with-docker.com/) — A simple, interactive, fun playground to learn Docker.
  * [quay.io](https://quay.io/) — Build and store container images with unlimited free public repositories
  * [ttl.sh](https://ttl.sh/) - Anonymous & ephemeral Docker image registry

**[⬆️ Back to Top](#table-of-contents)**

## Vagrant Related

  * [Vagrant Cloud](https://app.vagrantup.com) - HashiCorp Vagrant Cloud. Vagrant box hosting.

**[⬆️ Back to Top](#table-of-contents)**

## Dev Blogging Sites

  * [BearBlog](https://bearblog.dev/) - Minimalist, Markdown-powered blog and website builder.
  * [Dev.to](https://dev.to/) - Where programmers share ideas and help each other grow.
  * [Hashnode](https://hashnode.com/) — Hassle-free Blogging Software for Developers!.
  * [Medium](https://medium.com/) — Get more thoughtful about what matters to you.
  * [AyeDot](https://ayedot.com/) — Share your ideas, knowledge, and stories with the world for Free in the form of Modern multimedia short-format Miniblogs.

**[⬆️ Back to Top](#table-of-contents)**

## Commenting Platforms
  * [GraphComment](https://graphcomment.com/) - GraphComment is a comments platform that helps you build an active community from the website’s audience.
  * [Utterances](https://utteranc.es/) - A lightweight comments widget built on GitHub issues. Use GitHub issues for blog comments, wiki pages, and more!
  * [Disqus](https://disqus.com/) - Disqus is a networked community platform used by hundreds of thousands of sites all over the web.
  * [Remarkbox](https://www.remarkbox.com/) - Open source hosted comments platform, pay what you can for "One moderator on a few domains with complete control over behavior & appearance"
  * [IntenseDebate](https://intensedebate.com/) - A feature-rich comment system for WordPress, Tumblr, Blogger, and many other website platforms.

**[⬆️ Back to Top](#table-of-contents)**

## Screenshot APIs

  * [ApiFlash](https://apiflash.com) — A screenshot API based on Aws Lambda and Chrome. Handles full page, captures timing, and viewport dimensions.
  * [microlink.io](https://microlink.io/) – It turns any website into data such as metatags normalization, beauty link previews, scraping capabilities, or screenshots as a service. 250 requests/day every day free.
  * [ScreenshotAPI.net](https://screenshotapi.net/) - Screenshot API uses a straightforward API call to generate screenshots of any website. Built to scale and hosted on Google Cloud. Offers 100 free screenshots per month.
  * [screenshotbase.com](https://screenshotbase.com) - 300 free screenshots / month. Take screenshots from any url. Fast, free & scalable.
  * [screenshotlayer.com](https://screenshotlayer.com/) — Capture highly customizable snapshots of any website. Free 100 snapshots/month
  * [screenshotmachine.com](https://www.screenshotmachine.com/) — Capture 100 snapshots/month, png, gif and jpg, including full-length captures, not only home page
  * [PhantomJsCloud](https://PhantomJsCloud.com) — Browser automation and page rendering.  Free Tier offers up to 500 pages/day.  Free Tier since 2017.
  * [Webshrinker.com](https://webshrinker.com) — Web Shrinker provides website screenshots and domain intelligence API services. Free 100 requests/month.

**[⬆️ Back to Top](#table-of-contents)**

## Flutter Related and Building IOS Apps without Mac

  * [FlutLab](https://flutlab.io/) - FlutLab is a modern Flutter online IDE and the best place to create, debug, and build cross-platform projects. Build iOS (Without a Mac) and Android apps with Flutter.
  * [CodeMagic](https://codemagic.io/) - Codemagic is a fully hosted and managed CI/CD for mobile apps. You can build, test, and deploy with a GUI-based CI/CD tool. The free tier offers 500 free minutes/month and a Mac Mini instance with 2.3 GHz and 8 GB of RAM.
  * [FlutterFlow](https://flutterflow.io/) -  FlutterFlow is a browser-based drag-and-drop interface to build mobile app using flutter.

**[⬆️ Back to Top](#table-of-contents)**

## Browser-based hardware emulation written in Javascript

  * [JsLinux](https://bellard.org/jslinux) — a really fast x86 virtual machine capable of running Linux and Windows 2k.
  * [Jor1k](https://s-macke.github.io/jor1k/demos/main.html) —  an OpenRISC virtual machine capable of running Linux with network support.
  * [v86](https://copy.sh/v86) — an x86 virtual machine capable of running Linux and other OS directly into the browser.

**[⬆️ Back to Top](#table-of-contents)**

## Privacy Management
  * [Bearer](https://www.bearer.sh/) - Helps implement privacy by design via audits and continuous workflows so that organizations comply with GDPR and other regulations. The free tier is limited to smaller teams and the SaaS version only.
  * [Osano](https://www.osano.com/) - Consent management and compliance platform with everything from GDPR representation to cookie banners. The free tier offers basic features.
  * [Iubenda](https://www.iubenda.com/) - Privacy and cookie policies and consent management. The free tier offers limited privacy and cookie policy as well as cookie banners.
  * [Cookiefirst](https://cookiefirst.com/) - Cookie banners, auditing, and multi-language consent management solution. The free tier offers a one-time scan and a single banner.
  * [Ketch](https://www.ketch.com/) - Consent management and privacy framework tool. The free tier offers most features with a limited visitor count.
  * [Concord](https://www.concord.tech/) - Full data privacy platform, including consent management, privacy request handling (DSARs), and data mapping. Free tier includes core consent management features and they also provide a more advanced plan for free to verified open source projects.

**[⬆️ Back to Top](#table-of-contents)**

## Miscellaneous

  * [BackgroundStyler.com](https://backgroundstyler.com) - Create aesthetic screenshots of your code, text or images to share on social media.
  * [BinShare.net](https://binshare.net) - Create & share code or binaries. Available to share as a beautiful image e.g. for Twitter / Facebook post or as a link e.g. for chats or forums.
  * [Blynk](https://blynk.io) — A SaaS with API to control, build & evaluate IoT devices. Free Developer Plan with 5 devices, Free Cloud & data storage. Mobile Apps are also available.
  * [Bricks Note Calculator](https://free.getbricks.app/) - a note-taking app (PWA) with a powerful built-in multiline calculator.
  * [Carbon.now.sh](https://carbon.now.sh) - create and share code snippets in an aesthetic screenshot-like image format. Usually used to aesthetically share/show off code snippets on Twitter or blog posts.
  * [Code Time](https://www.software.com/code-time) - an extension for time-tracking and coding metrics in VS Code, Atom, IntelliJ, Sublime Text, and more.
  * [Codepng](https://www.codepng.app) - Create excellent snapshots from your source code to share on social media.
  * [CodeToImage](https://codetoimage.com/) - Create screenshots of code or text to share on social media.
  * [Cronhooks](https://cronhooks.io/) - Schedule on-time or recurring webhooks. The free plan allows 5 ad-hoc schedules.
  * [cron-job.org](https://cron-job.org) - Online cronjobs service. Unlimited jobs are free of charge.
  * [datelist.io](https://datelist.io) - Online booking / appointment scheduling system. Free up to 5 bookings per month, includes 1 calendar
  * [Domain Forward](https://domain-forward.com/) - A straightforward tool to forward any URL or Domain. Free up to 5 domains and 200k requests per month.
  * [Elementor](https://elementor.com) — WordPress website builder. Free plan available with 40+ Basic Widgets.
  * [Exif Editor](https://exifeditor.io/) — View, Edit, Scrub, Analyze image/photo metadata in-browser instantly - including GPS location and metadata.
  * [Format Express](https://www.format-express.dev) - Instant online format for JSON / XML / SQL.
  * [FOSSA](https://fossa.com/) - Scalable, end-to-end management for third-party code, license compliance and vulnerabilities.
  * [Hook Relay](https://www.hookrelay.dev/) - Add webhook support to your app without the hassles: done-for-you queueing, retries with backoff, and logging. The free plan has 100 deliveries per day, 14-day retention, and 3 hook endpoints.
  * [Hosting Checker](https://hostingchecker.co) - Check hosting information such as ASN, ISP, location and more for any domain, website or IP address. Also includes multiple hosting and DNS-related tools.
  * [kandi](https://kandi.openweaver.com/) — Jumpstart Application Development: build custom functions, and use cases, and complete applications faster through code snippets and open-source library reuse.
  * [Base64 decoder/encoder](https://devpal.co/base64-decode/) — Online free tool for decoding & encoding data.
  * [newreleases.io](https://newreleases.io/) - Receive notifications on email, Slack, Telegram, Discord, and custom webhooks for new releases from GitHub, GitLab, Bitbucket, Python PyPI, Java Maven, Node.js NPM, Node.js Yarn, Ruby Gems, PHP Packagist, .NET NuGet, Rust Cargo and Docker Hub.
  * [OnlineExifViewer](https://onlineexifviewer.com/) — View EXIF data online instantly for a photo including GPS location and metadata.
  * [PDFMonkey](https://www.pdfmonkey.io/) — Manage PDF templates in a dashboard, call the API with dynamic data, and download your PDF. Offers 300 free documents per month.
  * [Pika Code Screenshots](https://pika.style/templates/code-image) — Create beautiful, customizable screenshots from code snippets and VSCode using the extension.
  * [QuickType.io](https://quicktype.io/) - Quickly auto-generate models/class/type/interface and serializers from JSON, schema, and GraphQL for working with data quickly & safely in any programming language. Convert JSON into gorgeous, typesafe code in any language.
  * [RandomKeygen](https://randomkeygen.com/) - A free mobile-friendly tool that offers a variety of randomly generated keys and passwords you can use to secure any application, service, or device.
  * [ray.so](https://ray.so/) - Create beautiful images of your code snippets.
  * [readme.com](https://readme.com/) — Beautiful documentation made easy, free for Open Source.
  * [redirection.io](https://redirection.io/) — SaaS tool for managing HTTP redirections for businesses, marketing and SEO.
  * [redirect.pizza](https://redirect.pizza/) - Easily manage redirects with HTTPS support. The free plan includes 10 sources and 100,000 hits per month.
  * [Renamer.ai](https://renamer.ai) — AI-powered file renaming tool with OCR, metadata extraction, and automation for 20+ languages. Free tier: 15 files/month, including desktop app, batch rename, auto-rename, and normal support.
  * [ReqBin](https://reqbin.com/) — Post HTTP Requests Online. Popular Request Methods include GET, POST, PUT, DELETE, and HEAD. Supports Headers and Token Authentication. Includes a basic login system for saving your requests.
  * [Smartcar API](https://smartcar.com) - An API for cars to locate, get fuel tank, battery levels, odometer, unlock/lock doors, etc.
  * [snappify](https://snappify.com) - Enables developers to create stunning visuals. From beautiful code snippets to fully fletched technical presentations. The free plan includes up to 3 snaps at once with unlimited downloads and 5 AI-powered code explanations per month.
  * [Sunrise and Sunset](https://sunrisesunset.io/api/) - Get sunrise and sunset times for a given longitude and latitude.
  * [superfeedr.com](https://superfeedr.com/) — Real-time PubSubHubbub compliant feeds, export, analytics. Free with less customization
  * [SurveyMonkey.com](https://www.surveymonkey.com) — Create online surveys. Analyze the results online. The free plan allows only 10 questions and 100 responses per survey.
  * [Tiledesk](https://tiledesk.com) - Create chatbots and conversational apps. Bring them omnichannel: from your website (live chat widget) to WhatsApp. Free plan with unlimited chatbots.
  * [UUID Generator](https://newuuid.com/) - Generate UUID v1, UUID v4, UUID v7, GUID, Nil UUIDs, CUID v1/v2, NanoID, and ULID instantly with enterprise-grade
  performance and security
  * [Versionfeeds](https://versionfeeds.com) — Custom RSS feeds for releases of your favorite software. Have the latest versions of your programming languages, libraries, or loved tools in one feed. (The first 3 feeds are free)
  * [videoinu](https://videoinu.com) — Create and edit screen recordings and other videos online.
  * [Webacus](https://webacus.dev) — Access a wide range of free developer tools for encoding, decoding, and data manipulation.
  * [Volume Shader BM](https://volumeshaderbm.org) — Free browser-based GPU benchmark (WebGL). Helps developers test and compare shader performance reproducibly across browsers and devices.

**[⬆️ Back to Top](#table-of-contents)**

## Remote Desktop Tools

  * [Getscreen.me](https://getscreen.me) —  Free for 2 devices, no limits on the number and duration of sessions
  * [Apache Guacamole™](https://guacamole.apache.org/) — Open source clientless remote desktop gateway
  * [RemSupp](https://remsupp.com) — On-demand support and permanent access to devices (2 sessions/day for free)
  * [RustDesk](https://rustdesk.com/) - Open source virtual/remote desktop infrastructure for everyone!
  * [AnyDesk](https://anydesk.com) —  Free for 3 devices, no limits on the number and duration of sessions

**[⬆️ Back to Top](#table-of-contents)**

## Game Development

  * [itch.io](https://itch.io/game-assets) — Free/Paid assets like sprites, tile sets, and character packs.
  * [Gamefresco.com](https://gamefresco.com/) — Discover, collect, and share free game assets from game artists everywhere.
  * [GameDevMarket](https://gamedevmarket.net) — Free/Paid assets like 2D, 3D, Audio, GUI.
  * [OpenGameArt](https://opengameart.org) — OpenSource Game Assets like music, sounds, sprites, and gifs.
  * [CraftPix](https://craftpix.net) — Free/Paid assets like 2D, 3D, Audio, GUI, backgrounds, icons, tile sets, game kits.
  * [Game Icons](https://game-icons.net/) - Free styleable SVG/PNG icons provided under a CC-BY license.
  * [LoSpec](https://lospec.com/) — Online tools for creating pixel art and other restrictive digital art, lots of tutorials/pallet list available to choose from for your games
  * [ArtStation](https://www.artstation.com/) - MarketPlace for Free/Paid 2D, 3D assets & audios, icons, tile sets, game kits. Also, It can be used for showcasing your art portfolio.
  * [Rive](https://rive.app/community/) - Community assets as well as create your own game assets using its free plan.
  * [Poly Pizza](https://poly.pizza/) - Free low poly 3D assets
  * [3Dassets.one](https://3dassets.one/) - Over 8,000 free/paid 3D models, and PBR materials for making textures.
  * [Kenney](https://www.kenney.nl/assets/) - Free (CC0 1.0 Universal licensed) 2D, 3D, Audio, and UI game assets.
  * [Poliigon](https://www.poliigon.com/) - Free and paid textures (with variable resolution), models, HDRIs, and brushes. Offers free plugins to export to software like Blender.
  * [Freesound](https://freesound.org/) - Free collaborative sound library offerer with different CC licenses.

**[⬆️ Back to Top](#table-of-contents)**

## Other Free Resources

  * [Wikimint Developer](https://developer.wikimint.com/p/tools.html) - Always free tools for web developers that includes CSS minify unminify, image optimizer, image resizer, case convertor, CSS validator, JavaScript compiler, HTML editor, etc.
  * [ElevateAI](https://www.elevateai.com) - Get up to 200 hours of audio transcription for free every month.
  * [get.localhost.direct](https://get.localhost.direct) — A better `*.localhost.direct` Wildcard public CA signed SSL cert for localhost development with sub-domain support
  * [Framacloud](https://degooglisons-internet.org/en/) — A list of Free/Libre Open Source Software and SaaS by the French non-profit [Framasoft](https://framasoft.org/en/).
  * [github.com — FOSS for Dev](https://github.com/tvvocold/FOSS-for-Dev) — A hub of free and Open Source software for developers.
  * [GitHub Education](https://education.github.com/pack) — Collection of free services for students. Registration required.
  * [Markdown Tools](https://markdowntools.com) - Tools for converting HTML, CSVs, PDFs, JSON, and Excel files to and from Markdown
  * [Microsoft 365 Developer Program](https://developer.microsoft.com/microsoft-365/dev-program) — Get a free sandbox, tools, and other resources you need to build solutions for the Microsoft 365 platform. The subscription is a 90-day [Microsoft 365 E5 Subscription](https://www.microsoft.com/microsoft-365/enterprise/e5) (Windows excluded) which is renewable. It is renewed if you're active in development(measured using telemetry data & algorithms).
  * [PHPhub](https://phphub.net/) — A collection of PHP tools, including a formatter, validator, sandbox, regex tester, and more.
  * [Pyrexp](https://pythonium.net/regex) — Free web-based regex tester and visualizer for debugging regular expressions.
  * [RedHat for Developers](https://developers.redhat.com) — Free access to Red Hat products including RHEL, OpenShift, CodeReady, etc. exclusively for developers. Individual plan only. Free e-books are also offered for reference.
  * [sandbox.httpsms.com](https://sandbox.httpsms.com) — Send and receive test SMS messages for free.
  * [SimpleBackups.com](https://simplebackups.com/) — Backup automation service for servers and databases (MySQL, PostgreSQL, MongoDB) stored directly into cloud storage providers (AWS, DigitalOcean, and Backblaze). Provides a free plan for 1 backup.
  * [SnapShooter](https://snapshooter.com/) — Backup solution for DigitalOcean, AWS, LightSail, Hetzner, and Exoscale, with support for direct database, file system and application backups to s3 based storage. Provides a free plan with daily backups for one resource.
  * [Themeselection](https://themeselection.com/) — Selected high quality, modern design, professional and easy-to-use Free Admin Dashboard Template,
HTML Themes and UI Kits to create your applications faster!
  * [Web.Dev](https://web.dev/measure/) — This is a free tool that allows you to see the performance of your website and improve the SEO to get a higher rank list in search engines.
  * [SmallDev.tools](https://smalldev.tools/) — A free tool for developers that allows you to Encode/Decode various formats, Minify HTML/CSS/Javascript, Beautify, Generate Fake/Testing datasets in JSON/CSV & multiple other formats and many more features. With a delightful interface.
  * [UseCSV by Layercode](https://layercode.com/usecsv) — Add CSV and Excel import to your web app in minutes. Give your users an enjoyable and robust data import experience. Get Started for Free without any credit card details, and start integrating UseCSV today. You can create unlimited Importers and upload files up to 100Mb.
  * [Buttons Generator](https://markodenic.com/tools/buttons-generator/) — 100+ buttons you can use in your project.
  * [WrapPixel](https://www.wrappixel.com/) — Download High Quality Free and Premium Admin dashboard template created with Angular, React, VueJs, NextJS, and NuxtJS!
  * [Utils.fun](https://utils.fun/en) — All offline daily and development tools based on the browser's computing power, including watermark generation, screen recording, encoding and decoding, encryption and decryption, and code formatting, are completely free and do not upload any data to the cloud for processing.
  * [It tools](it-tools.tech) - Useful tools for developer and people working in IT.
  * [Free Code Tools](https://freecodetools.org/) — Effective code tools which are 100% free. Markdown editor, Code minifier/beautifier, QR code generator, Open Graph Generator, Twitter card Generator, and more.
  * [regex101](https://regex101.com/) — Free this website allows you to test and debug regular expressions (regex). It provides a regex editor and tester, as well as helpful documentation and resources for learning regex.
  * [Kody Tools](https://www.kodytools.com/dev-tools) — 100+ dev tools including formatter, minifier, and converter.
  * [AdminMart](https://adminmart.com/) — High-Quality Free and Premium Admin Dashboard and Website Templates created with Angular, Bootstrap, React, VueJs, NextJS, and NuxtJS!
  * [Glob tester](https://globster.xyz/) — A website that allows you to design and test glob patterns. It also provides resources to learn glob patterns.
  * [SimpleRestore](https://simplerestore.io) - Hassle-free MySQL backup restoration. Restore MySQL backups to any remote database without code or a server.
  * [360Converter](https://www.360converter.com/) - Free tier useful website to convert: Video to Text && Audio to Text && Speech to Text && Real-time Audio to Text && YouTube Video to Text && add Video Subtitle. Maybe it will be helpful in a short video conversion or in a short youtube tutorial:)
  * [QRCodeBest](https://qrcode.best/) - Create custom QR codes with 13 templates, full privacy, and personal branding. Features tracking pixels, project categorization, and unlimited team seats on QRCode.Best.
  * [PostPulse](https://PostPulseAI.com) - Boost your online presence, enhance your SEO and site ranking with monthly AI-crafted posts to SEO-optimized domains The free Plan allows you to manually publish one Post on our site every month.
  * [PageTools](https://pagetools.co/) - Offers a suite of forever free AI-powered tools to help you generate essential website policies, create social media bios, posts and web pages with a simple one-click interface.
  * [MySQL Visual Explain](https://mysqlexplain.com) - Easy-to-understand and free MySQL EXPLAIN output visualizer to optimize slow queries.
  * [Killer Coda](https://killercoda.com/)  - Interactive playground in your browser to study Linux, Kubernetes, Containers, Programming, DevOps, Networking
  * [Axonomy App](https://axonomy-app.com/) - A free tool to create, manage and share your invoices with your clients. 10 free invoices per month.
  * [Table Format Converter](https://www.tableformatconverter.com) - A free tool to convert table data to different formats, such as CSV, HTML, JSON, Markdown and more.


**[⬆️ Back to Top](#table-of-contents)**
