# free-for.dev

Developers and Open Source authors now have many services offering free tiers, but finding them all takes time to make informed decisions.

This is a list of software (SaaS, PaaS, IaaS, etc.) and other offerings with free developer tiers.

The scope of this particular list is limited to things that infrastructure developers (System Administrator, DevOps Practitioners, etc.) are likely to find useful. We love all the free services out there, but it would be good to keep it on topic. It's a grey line sometimes, so this is opinionated; please don't feel offended if I don't accept your contribution.

This list results from Pull Requests, reviews, ideas, and work done by 1100+ people. You can also help by sending [Pull Requests](https://github.com/ripienaar/free-for-dev) to add more services or remove ones whose offerings have changed or been retired.

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
    * Full, detailed list - https://cloud.google.com/free

  * [Amazon Web Services](https://aws.amazon.com)
    * [CloudFront](https://aws.amazon.com/cloudfront/) - 1TB egress per month and 2M Function invocations per month
    * [Cloudwatch](https://aws.amazon.com/cloudwatch/) - 10 custom metrics and ten alarms
    * [CodeBuild](https://aws.amazon.com/codebuild/) - 100min of build time per month
    * [CodeCommit](https://aws.amazon.com/codecommit/) - 5 active users,50GB storage, and 10000 requests per month
    * [CodePipeline](https://aws.amazon.com/codepipeline/) - 1 active pipeline per month
    * [DynamoDB](https://aws.amazon.com/dynamodb/) - 25GB NoSQL DB
     * [EC2](https://aws.amazon.com/ec2/) - 750 hours per month of t2.micro or t3.micro(12mo). 100GB egress per month
    * [EBS](https://aws.amazon.com/ebs/) - 30GB per month of General Purpose (SSD) or Magnetic(12mo)
    * [Elastic Load Balancing](https://aws.amazon.com/elasticloadbalancing/) - 750 hours per month(12mo)
    * [RDS](https://aws.amazon.com/rds/) - 750 hours per month of db.t2.micro, db.t3.micro, or db.t4g.micro, 20GB of General Purpose (SSD) storage, 20GB of storage backups
    * [Glacier](https://aws.amazon.com/glacier) - 10GB long-term object storage
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
    * Object Storage - 25GB per month
    * Cloudant database - 1 GB of data storage
    * Db2 database - 100MB of data storage
    * API Connect - 50,000 API calls per month
    * Availability Monitoring - 3 million data points per month
    * Log Analysis - 500MB of daily log
    * Full, detailed list - https://www.ibm.com/cloud/free/

  * [Cloudflare](https://www.cloudflare.com/)
    * [Application Services](https://www.cloudflare.com/plans/) - Free DNS for an unlimited number of domains, DDoS Protection, CDN along with free SSL, Firewall rules and page rules,  WAF, Bot Mitigation, Free Unmetered Rate Limiting - 1 rule per domain, Analytics, Email forwarding
    * [Zero Trust & SASE](https://www.cloudflare.com/plans/zero-trust-services/) - Up to 50 Users, 24 hours of activity logging, three network locations
    * [Cloudflare Tunnel](https://www.cloudflare.com/products/tunnel/) -  You can expose locally running HTTP port over a tunnel to a random subdomain on trycloudflare.com use [Quick Tunnels](https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/run-tunnel/trycloudflare), No account required. More features (TCP tunnel, Load balancing, VPN) in [Zero Trust](https://www.cloudflare.com/products/zero-trust/) Free Plan.
    * [Workers](https://developers.cloudflare.com/workers/) - Deploy serverless code for free on Cloudflare's global network—100k daily requests.
    * [Workers KV](https://developers.cloudflare.com/kv) - 100k read requests per day, 1000 write requests per day, 1000 delete requests per day, 1000 list requests per day, 1 GB stored data
    * [R2](https://developers.cloudflare.com/r2/) - 10 GB per month, 1 million Class A operations per month, 10 million Class B operations per month
    * [D1](https://developers.cloudflare.com/d1/) - 5 million rows read per day, 100k rows written per day, 1 GB storage
    * [Pages](https://developers.cloudflare.com/pages/) - Develop and deploy your web apps on Cloudflare's fast, secure global network. Five hundred monthly builds, 100 custom domains, Integrated SSL, unlimited accessible seats, unlimited preview deployments, and full-stack capability via Cloudflare Workers integration.
    * [Queues](https://developers.cloudflare.com/queues/) - 1 million operations per month

[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

## Cloud management solutions
  * [Brainboard](https://www.brainboard.co) - Collaborative solution to visually build and manage cloud infrastructures from end-to-end.
  * [Cloud 66](https://www.cloud66.com/) - Free for personal projects (includes one deployment server, one static site), Cloud 66 gives you everything you need to build, deploy, and grow your applications on any cloud without the headache of the “server stuff.”.
  * [Pulumi](https://www.pulumi.com/) — Modern infrastructure as a code platform that allows you to use familiar programming languages and tools to build, deploy, and manage cloud infrastructure.
  * [terraform.io](https://www.terraform.io/) — Terraform Cloud. Free remote state management and team collaboration for up to 500 resources.
  * [scalr.com](https://scalr.com/) - Scalr is a Terraform Automation and COllaboration (TACO) product used to better collaboration and automation on infrastructure and configurations managed by Terraform. Full Terraform CLI support, OPA integration, and a hierarchical configuration model. No SSO tax. All features are included. Use up to 50 runs/month for free.

[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

## Source Code Repos

  * [Bitbucket](https://bitbucket.org/) — Unlimited public and private Git repos for up to 5 users with Pipelines for CI/CD
  * [chiselapp.com](https://chiselapp.com/) — Unlimited public and private Fossil repositories
  * [codebasehq.com](https://www.codebasehq.com/) — One free project with 100 MB space and two users
  * [Codeberg.org](https://codeberg.org/) - Unlimited public and private Git repos for free and open-source projects. Static website hosting with [Codeberg Pages](https://codeberg.page/).
  * [GitGud](https://gitgud.io) — Unlimited private and public repositories. Free forever. Powered by GitLab & Sapphire. CI/CD not provided.
  * [GitHub](https://github.com/) — Unlimited public repositories and unlimited private repositories (with unlimited collaborators). Apart from this, some other free services(there are many more, but we list the main ones here) provided are :
       - [CI/CD](https://github.com/features/actions)(Free for Public Repos, 2000 min/month free for private repos)
       - [Codespaces](https://github.com/codespaces) - Development environments hosted in the cloud. 120-core hours and 15 GB codespaces storage available for free every month.
       - [Static Website Hosting](https://pages.github.com) (Free for Public Repos)
       - [Package Hosting & Container Registry](https://github.com/features/packages) (Free for public repos,500 MB storage & 1GB bandwidth outside CI/CD free for private repos)
       - Project Management and issue Tracking.
       - [GitHub Copilot](https://github.com/features/copilot) — AI pair programmer and completion tool powered by OpenAI Codex. Provides code review, autocompletion, documentation, and refactoring. Free for students via the GitHub Student Developer Pack.
  * [gitlab.com](https://about.gitlab.com/) — Unlimited public and private Git repos with up to 5 collaborators. Also offers the following features :
       - [CI/CD](https://about.gitlab.com/product/continuous-integration) (Free for Public Repos, 400 mins/month for private repos)
       - Static Sites with [GitLab Pages](https://about.gitlab.com/product/pages).
       - Container Registry with a 10 GB limit per repo.
       - Project Management and issue Tracking.
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

[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

## APIs, Data, and ML

  * [IP.City](https://ip.city) — 100 Free IP geolocation requests per day
  * [Abstract API](https://www.abstractapi.com) — API suite for various use cases, including IP geolocation, gender detection, or email validation.
  * [Apify](https://www.apify.com/) — Web scraping and automation platform to create an API for any website and extract data. Ready-made scrapers, integrated proxies, and custom solutions. Free plan with $5 platform credits included every month.
  * [APITemplate.io](https://apitemplate.io) - Auto-generate images and PDF documents with a simple API or automation tools like Zapier & Airtable. No CSS/HTML is required. The free plan comes with 50 images/month and three templates.
  * [APIToolkit.io](https://apitoolkit.io) - All the tools you need to fully understand what's going on in your APIs and Backends. With automatic API contract validation and monitoring. The free plan covers servers with up to 20,000 requests per month.
  * [Arize AI](https://arize.com/) - Machine learning observability for model monitoring and root-causing issues such as data quality and performance drift. Free up to two models.
  * [Atlas toolkit](https://atlastk.org/) - Lightweight library to develop single-page web applications that are instantly accessible. Available for Java, Node.js, Perl, Python, and Ruby.
  * [Beeceptor](https://beeceptor.com) - Mock a rest API in seconds, fake API response and much more. Free 50 requests per day, public dashboard, open endpoints (anyone with a dashboard link can view submissions and answers).
  * [bigml.com](https://bigml.com/) — Hosted machine learning algorithms. Unlimited free tasks for development, limit of 16 MB data/task.
  * [Browse AI](https://www.browse.ai) — Extracting and monitoring data on the web. Fifty credits per month for free.
  * [BrowserCat](https://www.browsercat.com) - Headless browser API for automation, scraping, AI agent web access, image/pdf generation, and more. Free plan with 1k requests per month.
  * [Bruzu](https://bruzu.com/) — Automate Image production. Generate tons of Image variants with API, Integrations, or nocode sheet. API is FREE with a watermark.
  * [Calendarific](https://calendarific.com) - Enterprise-grade Public holiday API service for over 200 countries. The free plan includes 1,000 calls per month.
  * [Canopy](https://www.canopyapi.co/) - GraphQL API for Amazon.com product, search, and category data. The free plan includes 100 calls per month.
  * [Clarifai](https://www.clarifai.com) — Image API for custom face recognition and detection. Able to train AI models. The free plan has 5,000 calls per month.
  * [Cloudmersive](https://cloudmersive.com/) — Utility API platform with full access to expansive API Library including Document Conversion, Virus Scanning, and more with 800 calls/month.
  * [Colaboratory](https://colab.research.google.com) — Free web-based Python notebook environment with Nvidia Tesla K80 GPU.
  * [Collect2](https://collect2.com) — Create an API endpoint to test, automate, and connect webhooks. The free plan allows for two datasets, 2000 records, one forwarder, and one alert.
  * [CometML](https://www.comet.com/site/) - The MLOps platform for experiment tracking, model production management, model registry, and complete data lineage, covering your workflow from training to production. Free for individuals and academics.
  * [Commerce Layer](https://commercelayer.io) - Composable commerce API that can build, place, and manage orders from any front end. The developer plan allows 100 orders per month and up to 1,000 SKUs for free.
  * [Conversion Tools](https://conversiontools.io/) - Online File Converter for documents, images, video, audio, and eBooks. REST API is available. Libraries for Node.js, PHP, Python. Support files up to 50 GB (for paid plans). The free tier is limited by file size and number of conversions per day.
  * [Coupler](https://www.coupler.io/) - Data integration tool that syncs between apps. It can create live dashboards and reports, transform and manipulate values, and collect and back up insights. The free plan has unlimited users, 100 runs with 1000 monthly rows, and unlimited integrations.
  * [CraftMyPDF](https://craftmypdf.com) - Auto-Generate PDF documents from reusable templates with a drop-and-drop editor and a simple API. The free plan comes with 100 PDFs/month and three templates.
  * [CurlHub](https://curlhub.io) — Proxy service for inspecting and debugging API calls. The free plan includes 10,000 requests per month.
  * [CurrencyScoop](https://currencyscoop.com) - Realtime currency data API for fintech apps. The free plan includes 5,000 calls per month.
  * [Cube](https://cube.dev/) - Cube helps data engineers and application developers access data from modern data stores, organize it into consistent definitions, and deliver it to every application. The fastest way to use Cube is with Cube Cloud, which has a free tier with 1GB of data passing through each month.
  * [Data Dead Drop](https://datadeaddrop.com) - Simple, free file sharing. Data self-destroys after access. Upload and download data via the browser or your favorite command line client.
  * [Data Fetcher](https://datafetcher.com) - Connect Airtable to any application or API with no code. Postman-like interface for running API requests in Airtable. Pre-built integrations with dozens of apps. The free plan includes 100 runs per month.
  * [Dataimporter.io](https://www.dataimporter.io) - Tool for connecting, cleaning, and importing data into Salesforce. Free Plan includes up to 20,000 records per month.
  * [Datalore](https://datalore.jetbrains.com) - Python notebooks by Jetbrains. Includes 10 GB of storage and 120 hours of runtime each month.
  * [Data Miner](https://dataminer.io/) - A browser extension (Google Chrome, MS Edge) for data extraction from web pages CSV or Excel. The free plan gives you 500 pages/month.
  * [Datapane](https://datapane.com) - API for building interactive reports in Python and deploying Python scripts and Jupyter Notebooks as self-service tools.
  * [DB-IP](https://db-ip.com/api/free) - Free IP geolocation API with 1k request per IP per day.lite database under the CC-BY 4.0 License is free too.
  * [DB Designer](https://www.dbdesigner.net/) — Cloud-based Database schema design and modeling tool with a free starter plan of 2 Database models and ten tables per model.
  * [DeepAR](https://developer.deepar.ai) — Augmented reality face filters for any platform with one SDK. The free plan provides up to 10 monthly active users (MAU) and tracks up to 4 faces
  * [Deepnote](https://deepnote.com) - A new data science notebook. Jupyter is compatible with real-time collaboration and running in the cloud. The free tier includes unlimited personal projects, up to 750 hours of standard hardware, and teams with up to 3 editors.
  * [Diggernaut](https://www.diggernaut.com/) — Cloud-based web scraping and data extraction platform for turning any website to the dataset or working with it as an API. The free plan includes 5K page requests monthly.
  * [Disease.sh](https://disease.sh/) — A free API providing accurate data for building the Covid-19 related useful Apps.
  * [Doczilla](https://www.doczilla.app/) — SaaS API empowering the generation of screenshots or PDFs directly from HTML/CSS/JS code. The free plan allows 250 documents month.
  * [dreamfactory.com](https://dreamfactory.com/) — Open source REST API backend for mobile, web, and IoT applications. Hook up any SQL/NoSQL database, file storage system, or external service, and it instantly creates a comprehensive REST API platform with live documentation and user management.
  * [DynamicDocs](https://advicement.io) - Generate PDF documents with JSON to PDF API based on LaTeX templates. The free plan allows 50 API calls per month and access to a library of templates.
  * [Efemarai](https://efemarai.com) - Testing and debugging platform for ML models and data. Visualize any computational graph. Free 30 debugging sessions per month for developers.
  * [Einblick](https://www.einblick.ai/) - a modern data science platform that brings Python notebooks to a collaborative canvas and includes tools that automate everyday tasks such as building predictive models (AutoML) or comparing populations. The free tier consists of 5 canvases and unlimited collaborators.
  * [Exspanse](https://exspanse.com) - MLOPS Platform to build, train and deploy ML models and AI solutions. The free plan allows the creation of unlimited projects, 5Gb of cloud storage, and five docker container images.
  * [ExtendsClass](https://extendsclass.com/rest-client-online.html) - Free web-based HTTP client to send HTTP requests.
  * [Export SDK](https://exportsdk.com) - PDF generator API with drag-and-drop template editor that provides an SDK and no-code integrations. The free plan has 250 monthly pages, unlimited users, and three templates.
  * [file.coffee](https://file.coffee/) - A platform where you can store up to 15MB/file (30/MB file with an account).
  * [Flatirons Fuse](https://flatironsdevelopment.com/products/fuse/) - An embeddable CSV and spreadsheet import tool that makes data to your website fast, easy, and painless.
  * [FraudLabs Pro](https://www.fraudlabspro.com) — Screen an order transaction for credit card payment fraud. This REST API will detect all possible fraud traits based on the input parameters of an order. The Free Micro plan has 500 transactions per month.
  * [Geekflare API](https://geekflare.com/api) - Geekflare API lets you take screenshots, audit websites, TLS scan, DNS lookup, test TTFB, and more. The free plan offers 3,000 API requests.
  * [GeoCod](https://geocod.xyz) — Free geocoding API: Convert postal addresses into geographic coordinates or convert geographic coordinates into postal addresses (reverse geocoding).
  * [GeoDataSource](https://www.geodatasource.com) — Location search service looks up city names using latitude and longitude coordinates. Free API queries up to 500 times per month.
  * [Glitterly](https://glitterly.app/) - Programmatically generate dynamic images from base templates. Restful API and nocode integrations. The free tier comes with 50 images/month and five templates.
  * [GoodData](https://www.gooddata.com/) - Data as a Service - Create interactive and insightful dashboards. The free tier comes with five workspaces and 100 MB/workspace.
  * [Hex](https://hex.tech/) - a collaborative data platform for notebooks, data apps, and knowledge libraries. Free community version with up to 3 authors and five projects. One compute profile per author with 4GB RAM.
  * [Hook0](https://www.hook0.com/) - Hook0 is an open-source Webhooks-as-a-service (WaaS) that makes it easy for online products to provide webhooks. Dispatch up to 3,000 events/month with seven days of history retention for free.
  * [Hoppscotch](https://hoppscotch.io) - A free, fast, and beautiful API request builder.
  * [Hybiscus](https://hybiscus.dev/) - Build pdf reports using a simple declarative API. The free tier includes up to 100 single-page reports per month with the ability to customize color palettes and fonts.
  * [Invantive Cloud](https://cloud.invantive.com/) — Access over 70 (cloud)platforms such as Exact Online, Twinfield, ActiveCampaign or Visma using Invantive SQL or OData4 (typically Power BI or Power Query). Includes data replication and exchange. Free plan for developers and implementation consultants. Free for specific platforms with limitations in data volumes.
  * [ipaddress.sh](https://ipaddress.sh) — Simple service to get a public IP address in different [formats](https://about.ipaddress.sh/).
  * [ipbase.com](https://ipbase.com) - IP Geolocation API - Forever free plan that spans 150 monthly requests.
  * [IP Geolocation](https://ipgeolocation.io/) — IP Geolocation API - Forever free plan for developers with 30k requests per month (1k/day) limit.
  * [IP Geolocation API](https://www.abstractapi.com/ip-geolocation-api) — IP Geolocation API from Abstract - Extensive free plan allowing 20,000 monthly requests.
  * [IP2Location](https://www.ip2location.com) — Freemium IP geolocation service. LITE database is available for free download. Import the database in the server and perform a local query to determine the city, coordinates, and ISP information.
  * [IP2Location.io](https://www.ip2location.io/) — Freemium, fast and reliable IP geolocation API to determine geolocation data like city, coordinates, ISP, etc. The free plan is available with 30k credits per month. Subscribe to paid plans for more advanced features or contact us for a personalized plan.
  * [ipapi](https://ipapi.co/) - IP Address Location API by Kloudend, Inc - A reliable geolocation API built on AWS, trusted by Fortune 500. The free tier offers 30k lookups/month (1k/day) without signup.
  * [ipapi.is](https://ipapi.is/) - A reliable IP Address API from Developers for Developers with the best Hosting Detection capabilities that exist. The free plan offers 1000 lookups without signup.
  * [IPinfo](https://ipinfo.io/) — Fast, accurate, and free (up to 50k/month) IP address data API. Offers APIs with details on geolocation, companies, carriers, IP ranges, domains, abuse contacts, and more. All paid APIs can be trialed for free.
  * [IPList](https://www.iplist.cc) — Lookup details about any IP address, such as Geo IP information, tor addresses, hostnames, and ASN details. Free for personal and business users.
  * [BigDataCloud](https://www.bigdatacloud.com/) - Provides fast, accurate, and free (Unlimited or up to 10K-50K/month) APIs for modern web like IP Geolocation, Reverse Geocoding, Networking Insights, Email and Phone Validation, Client Info and more.
  * [IPTrace](https://iptrace.io) — An embarrassingly simple API that provides your business with reliable and helpful IP geolocation data.
  * [JSON2Video](https://json2video.com) - A video editing API to automate video marketing and social media videos, programmatically or with no code.
  * [JSON IP](https://getjsonip.com) — Returns the Public IP address of the client it is requested from. No registration is required for the free tier. Using CORS, data can be requested using client-side JS directly from the browser. Useful for services monitoring change in client and server IPs. Unlimited Requests.
  * [konghq.com](https://konghq.com/) — API Marketplace and powerful private and public API tools. With the free tier, some features such as monitoring, alerting, and support, are limited.
  * [Kreya](https://kreya.app) — Free gRPC GUI client to call and test gRPC APIs. Can import gRPC APIs via server reflection.
  * [Lightly](https://www.lightly.ai/) — Improve your machine-learning models by using the correct data. Use datasets of up to 1000 samples for free.
  * [LoginLlama](https://loginllama.app) - A login security API to detect fraudulent and suspicious logins and notify your customers. Free for 1,000 logins per month.
  * [MailboxValidator](https://www.mailboxvalidator.com) — Email verification service using real mail server connection to confirm valid email. The free API plan has 300 verifications per month.
  * [Meteosource Weather API](https://www.meteosource.com/) — global weather API for current and forecasted weather data. Forecasts are based on a machine learning combination of more weather models to achieve better accuracy. The free plan comes with 400 calls per day.
  * [microlink.io](https://microlink.io/) – It turns any website into data such as metatags normalization, beauty link previews, scraping capabilities, or screenshots as a service. One hundred reqs/day, every day free.
  * [Mindee](https://developers.mindee.com/docs) – Mindee is a powerful OCR software and an API-first platform that helps developers automate applications' workflows by standardizing the document processing layer through data recognition for key information using computer vision and machine learning. The free tier offers 250 pages per month.
  * [monkeylearn.com](https://monkeylearn.com/) — Text analysis with machine learning, free 300 queries/month.
  * [MockAPI](https://www.mockapi.io/) — MockAPI is a simple tool that lets you quickly mock up APIs, generate custom data, and perform operations using a RESTful interface. MockAPI is meant to be a prototyping/testing/learning tool. One project/4 resources per project for free.
  * [Mockfly](https://www.mockfly.dev/) — Mockfly is a trusted development tool for API mocking and feature flag management. Quickly generate and control mock APIs with an intuitive interface. The free tier offers 500 requests per day.
  * [Mocki](https://mocki.io) - A tool that lets you create mock GraphQL and REST APIs synced to a GitHub repository. Simple REST APIs are free to develop and use without signup.
  * [Mocko.dev](https://mocko.dev/) — Proxy your API, choose which endpoints to mock in the cloud and inspect traffic, for free. Speed up your development and integration tests.
  * [Mocky](https://designer.mocky.io/) - A simple web app to generate custom HTTP responses for mocking HTTP requests. Also available as [open source](https://github.com/julien-lafont/Mocky).
  * [reqres.in](https://reqres.in) - A Free hosted REST-API ready to respond to your AJAX requests.
  * [microenv.com](https://microenv.com) —  Create fake REST API for developers with the possibility to generate code and app in a docker container.
  * [neptune.ai](https://neptune.ai/) - Log, store, display, organize, compare, and query all your MLOps metadata. Free for individuals: 1 member, 100 GB of metadata storage, 200h of monitoring/month
  * [News API](https://newsapi.org) — Search news on the web with code, and get JSON results. Developers get 3,000 queries free each month.
  * [Nordigen](https://nordigen.com) — Free open banking data API. PSD2. Connect 2300+ banks with your app/software in EU+UK.
  * [Nyckel](https://www.nyckel.com) — Train, deploy, and invoke image and text ML models. Free training with up to 5,000 pieces of training data. 1000 model invokes per month free.
  * [Observable](https://observablehq.com/) — a place to create, collaborate, and learn with data. Free: Unlimited notebooks, Unlimited publishing, Five editors per notebook.
  * [OCR.Space](https://ocr.space/) — An OCR API parses image and pdf files that return the text results in JSON format. Twenty-five thousand requests per month are free.
  * [Duply.co](https://duply.co) — Create dynamic images from API & URL, design template once and reuse it. The free tier offers 70 images/month creation from API & URL and Up to 100 through Form.
  * [OpenAPI3 Designer](https://openapidesigner.com/) — Visually create Open API 3 definitions for free.
  * [Orchest](https://orchest.io) — Visual pipeline editor and workflow orchestrator for data science, one instance for free, open source version available.
  * [parsehub.com](https://parsehub.com/) — Extract data from dynamic sites, turn dynamic websites into APIs, five projects free.
  * [pdfEndpoint.com](https://pdfendpoint.com) - Effortlessly convert HTML or URLs to PDF with a simple API. One hundred conversions per month for free.
  * [PDF Factory](https://pdf-factory.com) - PDF Automation API, visual template editor, dynamic data integration, and PDF rendering with an API. The free plan comes with one template, 100 PDFs/month.
  * [Pixela](https://pixe.la/) - Free daystream database service. All operations are performed by API. Visualization with heat maps and line graphs is also possible.
  * [Postbacks](https://postbacks.io/) - Request HTTP callbacks for a later time. Eight thousand free requests on signup.
  * [Postman](https://postman.com) — Simplify workflows and create better APIs – faster – with Postman, a collaboration platform for API development. Use the Postman App for free forever. Postman cloud features are also free forever with certain limits.
  * [PrefectCloud](https://www.prefect.io/cloud/) — A complete platform for dataflow automation. All plans include 20,000 free runs every month. That's enough to power ETL for most small businesses.
  * [Preset Cloud](https://preset.io/) - A hosted Apache Superset service. Forever free for teams of up to 5 users, featuring unlimited dashboards and charts, a no-code chart builder, and a collaborative SQL editor.
  * [PromptLeo](https://promptleo.com/) - Prompt engineering platform for creators and developers. It offers a prompt engineering library, forms, and API. The free plan provides one prompt formation, one prompt API endpoint, and 30 generations per month.
  * [PromptLoop](https://www.promptloop.com/) - Use AI and large language models like GPT-3 with a simple spreadsheet formula to transform, comprehend, and analyze text in Google Sheets. The first 2,000 credits are free each month.
  * [Crawlbase](https://crawlbase.com/) — Crawl and scrape websites without proxies, infrastructure, or browsers. We solve captchas for you and prevent you from being blocked. The first 1000 calls are free of charge.
  * [Public-Apis Github Repo](https://github.com/public-apis/public-apis) — A list of free public APIs.
  * [Supportivekoala](https://supportivekoala.com/) — Allows you to autogenerate images by your input via templates. The free plan allows you to create up to 100 images per week.
  * [QuickMocker](https://quickmocker.com/) — Manage online fake API endpoints under your own subdomain, forward requests to localhost URL for webhooks development and testing, use RegExp and multiple HTTP methods for URL path, prioritize endpoints, more than 100 shortcodes (dynamic or fake response values) for response templating, import from OpenAPI (Swagger) Specifications in JSON format, proxy requests, restrict endpoint by IP address and authorization header. The free account provides one random subdomain, ten endpoints, 5 RegExp URL paths, 50 shortcodes per endpoint, 100 requests per day, and 50 history records in the requests log.
  * [Rapidapi](https://rapidapi.com/) - World’s Largest API Hub Millions of developers find and connect to thousands of APIs, API Development using fun challenges (with solutions!) and interactive examples.
  * [RequestBin.com](https://requestbin.com) — Create a free endpoint to which you can send HTTP requests. Any HTTP requests sent to that endpoint will be recorded with the associated payload and headers so you can observe recommendations from webhooks and other services.
  * [Roboflow](https://roboflow.com) - create and deploy a custom computer vision model with no prior machine learning experience required. The free tier includes up to 1,000 free source images.
  * [ROBOHASH](https://robohash.org/) - Web service to generate unique and cool images from any text.
  * [SaturnCloud](https://saturncloud.io/) - Data science cloud environment that allows running Jupyter notebooks and Dask clusters. Thirty hours of free computation and 3 hours of Dask per month.
  * [Scraper's Proxy](https://scrapersproxy.com) — Simple HTTP proxy API for scraping. Scrape anonymously without having to worry about restrictions, blocks, or captchas. First 100 successful scrapes per month free including javascript rendering (more available if you contact support).
  * [ScrapingAnt](https://scrapingant.com/) — Headless Chrome scraping API and free checked proxies service. Javascript rendering, premium rotating proxies, CAPTCHAs avoiding. Free plans are available.
  * [ScraperBox](https://scraperbox.com/) — Undetectable web scraping API using real Chrome browsers and proxy rotation. Use a simple API call to scrape any web page. The free plan has 1000 requests per month.
  * [ScrapingDog](https://scrapingdog.com/) — Scrapingdog handles millions of proxies, browsers, and CAPTCHAs to provide you with the HTML of any web page in a single API call. It also includes Web Scraper for Chrome & Firefox and software for instant scraping demand. Free plans are available.
  * [scrapinghub.com](https://scrapinghub.com) — Data scraping with visual interface and plugins. The free plan includes unlimited scraping on a shared server.
  * [Simplescraper](https://simplescraper.io) — Trigger your webhook after each operation. The free plan includes 100 cloud scrape credits.
  * [Select Star](https://www.selectstar.com/) - is an intelligent data discovery platform that automatically analyzes and documents your data. Free light tier with 1 Data Source, up to 100 Tables and 10 Users.
  * [Sheetson](https://sheetson.com) - Instantly turn any Google Sheets into a RESTful API. Free plan available.
  * [Shipyard](https://www.shipyardapp.com) — Low-code data orchestration platform for the cloud. Build with a mix of low-code templates and your code (Python, Node.js, Bash, SQL). Our free developer plan offers 10 hours of runtime every month for one user - more than enough to automate multiple workflows.
  * [shrtcode API](https://shrtco.de/docs) - Free URL Shortening API without authorization and no request limits.
  * [SerpApi](https://serpapi.com/) - Real-time search engine scraping API. Returns structured JSON results for Google, YouTube, Bing, Baidu, Walmart, and many other machines. The free plan includes 100 successful API calls per month.
  * [Sofodata](https://www.sofodata.com/) - Create secure RESTful APIs from CSV files. Upload a CSV file and instantly access the data via its API allowing faster application development. The free plan includes 2 APIs and 2,500 API calls per month. You don't need a credit card.
  * [Stoplight](https://stoplight.io/) - Saas for collaboratively designing and documenting for APIs. The free plan offers free design, mocking, and documentation tools.
  * [Svix](https://www.svix.com/) - Webhooks as a Service. Send up to 50,000 messages/month for free.
  * [TemplateTo](https://templateto.com) - Auto-Generate PDF/TXT documents from reusable templates with our drop-and-drop editor and simple API. The free plan comes with 450 PDFs/month and three templates.
  * [TinyMCE](https://www.tiny.cloud) - rich text editing API. Core features are free for unlimited usage.
  * [Webhook Store](https://www.openwebhook.io) - Tool for storing third-party webhooks and debug them on localhost (ngrok style). Open source and self-hostable. Free personal domain *username*.github.webhook.store, free public domains *anything*.webhook.store.
  * [Weights & Biases](https://wandb.ai) — The developer-first MLOps platform. Build better models faster with experiment tracking, dataset versioning, and model management. Free tier for personal projects only, with 100 GB of storage included.
  * [wit.ai](https://wit.ai/) — NLP for developers.
  * [wolfram.com](https://wolfram.com/language/) — Built-in knowledge-based algorithms in the cloud.
  * [wrapapi.com](https://wrapapi.com/) — Turn any website into a parameterized API. 30k API calls per month.
  * [ZenRows](https://www.zenrows.com/) — Web Scraping API & proxy server that bypasses any anti-bot solution while offering javascript rendering, rotating proxies, and geotargeting. The free tier of 1000 API calls.
  * [Zenscrape](https://zenscrape.com/web-scraping-api) — Web scraping API with headless browsers, residentials IPs, and straightforward pricing. One thousand free API calls/month and extra credits for students and non-profits.
  * [ip-api](https://ip-api.com) — IP Geolocation API, Free for non-commercial use, no API key required, limited to 45 req/minute from the same IP address for the free plan.
  * [WebScraping.AI](https://webscraping.ai) - Simple Web Scraping API with built-in parsing, Chrome rendering, and proxies. Two thousand free API calls per month.
  * [Zipcodebase](https://zipcodebase.com) - Free Zip Code API, access to Worldwide Postal Code Data. Ten thousand free requests/month.
  * [huggingface.co](https://huggingface.co) - Build, train, and deploy NLP models for Pytorch, TensorFlow, and JAX. Free up to 30k input characters/mo.
  * [vatcheckapi.com](https://vatcheckapi.com) - Simple and free VAT number validation API. Five hundred free requests per month.
  * [numlookupapi.com](https://numlookupapi.com) - Free phone number validation API - 100k free requests / month.
  * [Volca](https://volca.io#api) - Free API providing lists of technologies such as programming languages and database systems. Unlimited free requests.
  * [Query.me](https://query.me) - Collaborative data notebooks that execute script-like and allow to fetch and send data via SQL, API, and many custom blocks, like Slack and Email. Free for small Teams.
* [ERD Lab](https://www.erdlab.io) —  Free cloud-based entity relationship diagram (ERD) tool made for developers.
* [What The Diff](https://whatthediff.ai) - AI-powered code review assistant. The free plan has a limit of 25,000 monthly tokens (~10 PRs).
* [Zipcodestack](https://zipcodestack.com) - Free Zip Code API and Postal Code Validation. Ten thousand free requests/month.
* [Zuplo](https://zuplo.com/) - Add API Key authentication, rate limiting, and developer documentation to any API in minutes. The free plan offers up to 10 projects, unlimited production edge environments, 250 API keys, 100K monthly requests, and 1GB egress.
* [OpenWeb Ninja](https://www.openwebninja.com/) - Extremely comprehensive real-time SERP and public data APIs: Google Search, Shopping, Jobs, Images, Lens, News, Google Maps Businesses / Places, Reviews, Photos, Website Emails and Social Contacts Scraper, Amazon, Yelp and more. All APIs include a free tier with 100 to 200 free monthly requests.
* [Tavily AI](https://tavily.com/) - API for online serach and rapid insights and comprehensive research, with the capability of organization of research results. 1000 request/month for the Free tier with No credit card required.

[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

## Artifact Repos

 * [Artifactory](https://jfrog.com/start-free/) - An artifact repository that supports numerous package formats like Maven, Docker, Cargo, Helm, PyPI, CocoaPods, and GitLFS. Includes package scanning tool XRay and CI/CD tool Pipelines (formerly Shippable) with a free tier of 2,000 CI/CD minutes per month.
 * [central.sonatype.org](https://central.sonatype.org) — The default artifact repository for Apache Maven, SBT, and other build systems.
 * [cloudrepo.io](https://cloudrepo.io) - Cloud-based, private and public, Maven and PyPi repositories. Free for open-source projects.
 * [cloudsmith.io](https://cloudsmith.io) — Simple, secure, and centralized repository service for Java/Maven, RedHat, Debian, Python, Ruby, Vagrant, and more. Free tier + free for open source.
 * [jitpack.io](https://jitpack.io/) — Maven repository for JVM and Android projects on GitHub, free for public projects.
 * [packagecloud.io](https://packagecloud.io/users/new?plan=free_usage_plan) — Easy to use repository hosting for Maven, RPM, DEB, PyPi, NPM, and RubyGem packages (has free tier).
 * [repsy.io](https://repsy.io) — 1 GB Free private/public Maven Repository.
 * [Gemfury](https://gemfury.com) — Private and public artifact repos for Maven, PyPi, NPM, Go Module, Nuget, APT, and RPM repositories. Free for public projects.
 * [paperspace](https://www.paperspace.com/) — Build & scale AI models, Develop, train, and deploy AI applications, free plan: public projects, 5Gb storage, basic instances.

[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

## Tools for Teams and Collaboration

  * [3Cols](https://3cols.com/) - A free cloud-based code snippet manager for personal and collaborative code.
  * [Bitwarden](https://bitwarden.com) — The easiest and safest way for individuals, teams, and business organizations to store, share, and sync sensitive data.
  * [Braid](https://www.braidchat.com/) — Chat app designed for teams. Free for public access group, unlimited users, history, and integrations. also, it provides a self-hostable open-source version.
  * [cally.com](https://cally.com/) — Find the perfect time and date for a meeting. Simple to use, works great for small and large groups.
  * [Calendly](https://calendly.com) — Calendly is the tool for connecting and scheduling meetings. The free plan provides 1 Calendar connection per user and Unlimited sessions. Desktop and Mobile apps are also offered.
  * [Discord](https://discord.com/) — Chat with public/private rooms. Markdown text, voice, video, and screen sharing capabilities. Free for unlimited users.
  * [Telegram](https://telegram.org/) — Telegram is for everyone who wants fast, reliable messaging and calls. Business users and small teams may like the large groups, usernames, desktop apps, and powerful file-sharing options.
  * [Duckly](https://duckly.com/) — Talk and collaborate in real time with your team. Pair programming with IDE, terminal sharing, voice, video, and screen sharing. Free for small teams.
  * [Dyte](https://dyte.io) - The most developer-friendly live video & audio SDK, featuring collaborative plugins to enhance productivity and engagement. The free tier includes monthly 10,000 minutes of live video/audio usage.
  * [evernote.com](https://evernote.com/) — Tool for organizing information. Share your notes and work together with others
  * [Fibery](https://fibery.io/) — Connected workspace platform. Free for single users, up to 2 GB disk space.
  * [Filestash](https://www.filestash.app) — A Dropbox-like file manager that connects to a range of protocols and platforms: S3, FTP, SFTP, Minio, Git, WebDAV, Backblaze, LDAP and more.
  * [flock.com](https://flock.com) — A faster way for your team to communicate. Free Unlimited Messages, Channels, Users, Apps & Integrations
  * [Gather](https://www.gather.town/) - A better way to meet online. Centered around fully customizable spaces, Gather makes spending time with your communities just as easy as real life. Free for up to 10 concurrent users.
  * [gokanban.io](https://gokanban.io) - Syntax-based, no registration Kanban Board for fast use. Free with no limitations.
  * [flat.social](https://flat.social) - Interactive customizable spaces for team meetings & happy hours socials. Unlimited meetings, free up to 8 concurrent users.
  * [GitDailies](https://gitdailies.com) - Daily reports of your team's Commit and Pull Request activity on GitHub. Includes Push visualizer, peer recognition system, and custom alert builder. The free tier has unlimited users, three repos, and 3 alert configs.
  * [gitter.im](https://gitter.im/) — Chat, for GitHub. Unlimited public and private rooms, free for teams of up to 25
  * [Hackmd.io](https://hackmd.io/) - Real time collaboration & writing tool for markdown format docs/files. Like Google but for markdown files. Free unlimited number of "notes", but the number of collaborators (invitee) for private notes & template [will be limited](https://hackmd.io/pricing).
  * [hangouts.google.com](https://hangouts.google.com/) — One place for all your conversations, for free, need a Google account
  * [HeySpace](https://hey.space) - Task management tool with chat, calendar, timeline and video calls. Free for up to 5 users.
  * [helplightning.com](https://www.helplightning.com/) — Help over video with augmented reality. Free without analytics, encryption, support
  * [ideascale.com](https://ideascale.com/) — Allow clients to submit ideas and vote, free for 25 members in 1 community
  * [Igloo](https://www.igloosoftware.com/) — Internal portal for sharing documents, blogs, calendars, etc. Free for up to 10 users.
  * [Keybase](https://keybase.io/) — Keybase is a FOSS alternative to Slack; it keeps everyone's chats and files safe, from families to communities to companies.
  * [Google Meet](https://meet.google.com/) — Use Google Meet for your business's online video meeting needs. Meet provides secure, easy-to-join online meetings.
  * [/meet for Slack](https://meetslack.com) - Start Google Meetings directly from Slack by using /meet in any channel, group, or DM. Free without any limitations.
  * [Livecycle](https://www.livecycle.io/) — Livecycle is an inclusive collaboration platform that makes workflows frictionless for cross-functional product teams and open-source projects.
  * [MarkUp](https://www.markup.io/) — MarkUp lets you collect feedback directly on top of your websites, PDFs and images.
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
  * [Slab](https://slab.com/) — A modern knowledge management service for teams. Free for up to 10 users.
  * [slack.com](https://slack.com/) — Free for unlimited users with some feature limitations
  * [Spectrum](https://spectrum.chat/) - Create public or private communities for free.
  * [StatusPile](https://www.statuspile.com/) - A status page of status pages. Could you track the status pages of your upstream providers?
  * [Stickies](https://stickies.app/) - Visual collaboration app used for brainstorming, content curation, and notes. Free for up to 3 Walls, unlimited users, and 1 GB storage.
  * [talky.io](https://talky.io/) — Free group video chat. Anonymous. Peer‑to‑peer. No plugins, signup, or payment required
  * [Teamhood](https://teamhood.com/) - Free Project, Task, and Issue-tracking software. Supports Kanban with Swimlanes and full Scrum implementation. Has integrated time tracking. Free for five users and three project portfolios.
  * [Teamplify](https://teamplify.com) - improve team development processes with Team Analytics and Smart Daily Standup. Includes full-featured Time Off management for remote-first teams. Free for small groups of up to 5 users.
  * [Tefter](https://tefter.io) - Bookmarking app with a powerful Slack integration. Free for open-source teams.
  * [TeleType](https://teletype.oorja.io/) — share terminals, voice, code, whiteboard, and more. no sign-in is required for end-to-end encrypted collaboration for developers.
  * [TimeCamp](https://www.timecamp.com/) - Free time tracking software for unlimited users. Easily integrates with PM tools like Jira, Trello, Asana, etc.
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
  * [shtab.app](https://shtab.app/) - Project management service that makes collaboration in the office remotely transparent with a tracker based on AI.
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

[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

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

[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

## Code Generation

  * [Appinvento](https://appinvento.io/) — AppInvento is a free No code app builder. In the automatically generated backend code, users have complete access to the source code and unlimited APIs and routes, allowing for extensive integration. The free plan includes three projects, five tables, and a Google add-on.
  * [DhiWise](https://www.dhiwise.com/) — Seamlessly turn Figma designs into dynamic Flutter & React applications with DhiWise's innovative code generation technology, optimizing your workflow and helping you craft exceptional mobile and web experiences faster than ever before.
  * [Codeium](https://www.codeium.com/) — Codeium is a free AI-powered code completion tool. It supports over 20+ programming languages (Python, JavaScript, Java, TypeScript, PHP, C/C++, Go, etc.) and integrates with all significant standalone and web IDEs.
  * [Metalama](https://www.postsharp.net/metalama) - Only for C#. Metalama generates the boilerplate of the code on the fly during compilation so that your source code remains clean. It is free for open-source projects, and its commercial-friendly free tier includes three aspects.
  * [tabnine.com](https://www.tabnine.com/) — Tabnine helps developers create better software faster by providing insights learned from all the code in the world. Plugin available.
  * [v0.dev](https://v0.dev/) — v0 uses AI models to generate code based on simple text prompts. It generates copy-and-paste friendly React code based on shadcn/ui and Tailwind CSS that people can use in their projects. Each generation takes at minimum 30 credits. You start up with 1200 credits, and get 200 free credits every month.


[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

## Code Quality

  * [beanstalkapp.com](https://beanstalkapp.com/) — A complete workflow to write, review, and deploy code), a free account for one user, and one repository with 100 MB of storage
  * [browserling.com](https://www.browserling.com/) — Live interactive cross-browser testing, free only 3 minutes sessions with MS IE 9 under Vista at 1024 x 768 resolution
  * [codacy.com](https://www.codacy.com/) — Automated code reviews for PHP, Python, Ruby, Java, JavaScript, Scala, CSS, and CoffeeScript, free for unlimited public and private repositories
  * [Codeac.io](https://www.codeac.io/infrastructure-as-code.html?ref=free-for-dev) - Automated Infrastructure as Code review tool for DevOps integrates with GitHub, Bitbucket, and GitLab (even self-hosted). In addition to standard languages, it also analyzes Ansible, Terraform, CloudFormation, Kubernetes, and more. (open-source free)
  * [CodeBeat](https://codebeat.co) — Automated Code Review Platform available for many languages. Free forever for public repositories with Slack and e-mail integration.
  * [codeclimate.com](https://codeclimate.com/) — Automated code review, free for Open Source and unlimited organisation-owned private repos (up to 4 collaborators). Also free for students and institutions.
  * [codecov.io](https://codecov.io/) — Code coverage tool (SaaS), free for Open Source and one free private repo
  * [CodeFactor](https://www.codefactor.io) — Automated Code Review for Git. The free version includes unlimited users, public repositories, and one private repo.
  * [codescene.io](https://codescene.io/) - CodeScene prioritizes technical debt based on how the developers work with the code and visualizes organizational factors like team coupling and system mastery. Free for Open Source.
  * [CodSpeed](https://codspeed.io) - Automate performance tracking in your CI pipelines. Catch performance regressions before deployment, thanks to precise and consistent metrics. Free forever for Open Source projects.
  * [coveralls.io](https://coveralls.io/) — Display test coverage reports, free for Open Source
  * [dareboost](https://dareboost.com) - 5 free analysis reports for web performance, accessibility, and security each month
  * [deepcode.ai](https://www.deepcode.ai) — DeepCode finds bugs, security vulnerabilities, performance and API issues based on AI. DeepCode's speed of analysis allows us to analyze your code in real time and deliver results when you hit the save button in your IDE. Supported languages are Java, C/C++, JavaScript, Python, and TypeScript. Integrations with GitHub, BitBucket, and GitLab. Free for open source and private repos and up to 30 developers.
  * [deepscan.io](https://deepscan.io) — Advanced static analysis for automatically finding runtime errors in JavaScript code, free for Open Source
  * [DeepSource](https://deepsource.io/) - DeepSource continuously analyzes source code changes, finding and fixing issues categorized under security, performance, anti-patterns, bug-risks, documentation, and style. Native integration with GitHub, GitLab, and Bitbucket.
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
  * [Viezly](https://viezly.com/) - Enhanced code review tool for easier code reading and navigation. Free for Open Source and free for personal usage.
  * [webceo.com](https://www.webceo.com/) — SEO tools but with also code verifications and different types of devices
  * [zoompf.com](https://zoompf.com/) — Fix the performance of your web sites, detailed analysis

[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

## Code Search and Browsing

  * [libraries.io](https://libraries.io/) — Search and dependency update notifications for 32 different package managers, free for open source
  * [Namae](https://namae.dev/) - Search various websites like GitHub, Gitlab, Heroku, Netlify, and many more for the availability of your project name.
  * [searchcode.com](https://searchcode.com/) — Comprehensive text-based code search, free for Open Source
  * [sourcegraph.com](https://about.sourcegraph.com/) — Java, Go, Python, Node.js, etc., code search/cross-references, free for Open Source
  * [tickgit.com](https://www.tickgit.com/) — Surfaces `TODO` comments (and other markers) to identify areas of code worth returning to for improvement.
  * [CodeKeep](https://codekeep.io) - Google Keep for Code Snippets. Organize, Discover, and share code snippets, featuring a powerful code screenshot tool with preset templates and a linking feature.

[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

## CI and CD

  * [AccessLint](https://github.com/marketplace/accesslint) — AccessLint brings automated web accessibility testing into your development workflow. It's free for open source and education purposes.
  * [appcircle.io](https://appcircle.io) — Automated mobile CI/CD/CT for iOS and Android with online emulators. 20-minute build timeout (60 minutes for Open Source) with single concurrency for free.
  * [appveyor.com](https://www.appveyor.com/) — CD service for Windows, free for Open Source
  * [Argonaut](https://argonaut.dev/) - Deploy apps and infrastructure on your cloud in minutes. Support for custom and third-party app deployments on Kubernetes and Lambda environments. The free tier allows unlimited apps and deployments for 5 domains and 2 users.
  * [bitrise.io](https://www.bitrise.io/) — A CI/CD for mobile apps, native or hybrid. With 200 free builds/month 10 min build time and two team members. OSS projects get 45 min build time, +1 concurrency and unlimited team size.
  * [buddy.works](https://buddy.works/) — A CI/CD with five free projects and one concurrent run (120 executions/month)
  * [buddybuild.com](https://www.buddybuild.com/) — Build, deploy, and gather feedback for your iOS and Android apps in one seamless, iterative system
  * [Buildkite](https://buildkite.com)
    * Pipelines: Free developer tier includes unlimited concurrency, up to 3 users, 5k job minutes/month, and 30-day build retention, with more free inclusions for open source projects
    * [Test Analytics](https://buildkite.com/test-analytics) — Get more out of your test suites, works with any CI platform. The free developer tier includes 100k test executions/month, with more free inclusions for open-source projects.
  * [bytebase.com](https://www.bytebase.com/) — Database CI/CD and DevOps. Free under 20 users and ten database instances
  * [CircleCI](https://circleci.com/) — Comprehensive free plan with all features included in a hosted CI/CD service for GitHub, GitLab, and BitBucket repositories. Multiple resource classes, Docker, Windows, Mac OS, ARM executors, local runners, test splitting, Docker Layer Caching, and other advanced CI/CD features. Free for up to 6000 minutes/month execution time, unlimited collaborators, 30 parallel jobs in private projects, and up to 80,000 free build minutes for Open Source projects.
  * [cirrus-ci.org](https://cirrus-ci.org) - Free for public GitHub repositories
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
  * [Mergify](https://mergify.io) — workflow automation and merge queue for GitHub — Free for public GitHub repositories
  * [Make](https://www.make.com/en) — The workflow automation tool lets you connect apps and automate workflows using UI. It supports many apps and the most popular APIs. Free for public GitHub repositories, and free tier with 100 Mb, 1000 Operations, and 15 minutes of minimum interval.
  * [Spacelift](https://spacelift.io/) - Management platform for Infrastructure as Code. Free plan features: IaC collaboration, Terraform module registry, ChatOps integration, Continuous resource compliance with Open Policy Agent, SSO with SAML 2.0, and access to public worker pools: up to 200 minutes/month
  * [microtica.com](https://microtica.com/) - Startup environments with ready-made infrastructure components, deploy apps on AWS for free, and support your production workloads. The free tier includes 1 Environment (on your AWS account), 2 Kubernetes Services, 100 build minutes per month, and 20 monthly deployments.


[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

## Testing

  * [Applitools.com](https://applitools.com/) — Smart visual validation for web, native mobile and desktop apps. Integrates with almost all automation solutions (like Selenium and Karma) and remote runners (Sauce Labs, Browser Stack). free for open source. A free tier for a single user with limited checkpoints per week.
  * [Appetize](https://appetize.io) — Test your Android & iOS apps on this Cloud Based Android Phone / Tablets emulator and iPhone/iPad simulators directly in your browser. The free tier includes one concurrent session with 100 minutes of usage per month. No limit on app size.
  * [Apptim](https://apptim.com) — A mobile testing tool that enables people without performance engineering skills to evaluate an app's performance and user experience (UX). A desktop version using your own device is 100% FREE, with unlimited tests on both iOS and Android.
  * [Bencher](https://bencher.dev/) - A continuous benchmarking tool suite to catch CI performance regressions. Free for all public projects.
  * [BugBug](https://bugbug.io/) - Lightweight test automation tool for web applications. It is easy to learn and doesn't require coding. You can run unlimited tests on your own computer for free. You also get cloud monitoring and CI/CD integration for an additional monthly fee.
  * [lambdatest.com](https://www.lambdatest.com/) — Manual, visual, screenshot, and automated browser testing on selenium and cypress, [free for Open Source](https://www.lambdatest.com/open-source-cross-browser-testing-tool)
  * [browserstack.com](https://www.browserstack.com/) — Manual and automated browser testing, [free for Open Source](https://www.browserstack.com/open-source?ref=pricing)
  * [checkbot.io](https://www.checkbot.io/) — Browser extension that tests if your website follows 50+ SEO, speed and security best practices. Free tier for smaller websites.
  * [checklyhq.com](https://checklyhq.com) - Checkly is the API & E2E monitoring platform for the modern stack: programmable, flexible and loving JavaScript. Generous free tier for devs.
  * [crossbrowsertesting.com](https://crossbrowsertesting.com) - Manual, Visual, and Selenium Browser Testing in the cloud - [free for Open Source](https://crossbrowsertesting.com/open-source)
  * [cypress.io](https://www.cypress.io/) - Fast, easy and reliable testing for anything that runs in a browser. Cypress Test Runner is always free and open-source with no restrictions and limitations. Cypress Dashboard is free for open-source projects for up to 5 users.
  * [Cypress Recorder by Preflight](https://cypress.preflight.com/) - Create AI-powered Cypress Tests/POM models on your browser. It's open-source, except for the AI part. It's free for five monthly test creations with Self-healing scripts, Email, and Visual testing.
  * [everystep-automation.com](https://www.everystep-automation.com/) — Records and replays all steps made in a web browser and creates scripts, free with fewer options
  * [Gremlin](https://www.gremlin.com/gremlin-free-software) — Gremlin's Chaos Engineering tools allow you to safely and securely inject failure into your systems to find weaknesses before they cause customer-facing issues. Gremlin Free provides access to Shutdown and CPU attacks on up to 5 hosts or containers.
  * [gridlastic.com](https://www.gridlastic.com/) — Selenium Grid testing with a free plan of up to 4 simultaneous selenium nodes/10 grid starts/4,000 test minutes/month
  * [katalon.com](https://katalon.com) - Provides a testing platform that can help teams of all sizes at different levels of testing maturity, including  Katalon Studio, TestOps (+ Visual Testing free), TestCloud, and Katalon Recorder.
  * [Keploy](https://keploy.io/) - Keploy is a functional testing toolkit for developers. Recording API calls generates E2E tests for APIs (KTests) and mocks or stubs(KMocks). It is free for Open Source projects.
  * [loadmill.com](https://www.loadmill.com/) - Automatically create API and load tests by analyzing network traffic. Simulate up to 50 concurrent users for up to 60 minutes for free monthly.
  * [octomind.dev](https://www.octomind.dev/) - Auto-generated, run and maintained Playwright UI tests with AI-assisted test case generation
  * [preflight.com](https://preflight.com) - No-code automated web testing. Record tests on your browser that are resilient to UI changes and run them on Windows machines. Could you integrate with your CI/CD? The free plan includes 50 monthly test runs with video, HTML sessions, and more.
  * [percy.io](https://percy.io) - Add visual testing to any web app, static site, style guide, or component library.  Unlimited team members, Demo app, and unlimited projects, 5,000 snapshots/month.
  * [lost-pixel.com](https://lost-pixel.com) - holistic visual regression testing for your Storybook, Ladle, Histoire stories and Web Apps. Unlimited team members, totally free for open-source, 7,000 snapshots/month.
  * [seotest.me](https://seotest.me/) — Free on-page SEO website tester. 10 free website crawls per day. Useful SEO learning resources and recommendations on how to improve the on-page SEO results for any website regardless of technology.
  * [snippets.uilicious.com](https://snippets.uilicious.com) - It's like CodePen but for cross-browser testing. UI-licious lets you write tests like user stories and offers a free platform - UI-licious Snippets - that allows you to run unlimited tests on Chrome with no sign-up required for up to 3 minutes per test run. Found a bug? You can copy the unique URL to your test to show your devs exactly how to reproduce the bug.
  * [testingbot.com](https://testingbot.com/) — Selenium Browser and Device Testing, [free for Open Source](https://testingbot.com/open-source)
  * [Testspace.com](https://testspace.com/) - A Dashboard for publishing automated test results and a Framework for implementing manual tests as code using GitHub. The service is [free for Open Source](https://github.com/marketplace/testspace-com) and accounts for 450 monthly results.
  * [tesults.com](https://www.tesults.com) — Test results reporting and test case management. Integrates with popular test frameworks. Open Source software developers, individuals, educators, and small teams getting started can request discounted and free offerings beyond basic free projects.
  * [websitepulse.com](https://www.websitepulse.com/tools/) — Various free network and server tools.
  * [qase.io](https://qase.io) - Test management system for Dev and QA teams. Manage test cases, compose test runs, perform tests, track defects, and measure impact. The free tier includes all core features, with 500MB available for attachments and up to 3 users.
  * [knapsackpro.com](https://knapsackpro.com) - Speed up your tests with optimal test suite parallelization on any CI provider. Split Ruby, JavaScript tests on parallel CI nodes to save time. Free plan for up to 10 minutes of test files and free unlimited plan for Open Source projects.
  * [webhook.site](https://webhook.site) - Verify webhooks, outbound HTTP requests, or emails with a custom URL. A temporary URL and email address are always free.
  * [webhookbeam.com](https://webhookbeam.com) - Set up webhooks and monitor them via push notifications and emails.
  * [Vaadin](https://vaadin.com) — Build scalable UIs in Java or TypeScript, and use the integrated tooling, components, and design system to iterate faster, design better, and simplify the development process. Unlimited Projects with five years of free maintenance.
  * [webhook-test.com](https://webhook-test.com) - Debug and inspect webhooks and HTTP requests with a unique URL during integration. Completely free, you can create unlimited URLs and receive recommendations.
  * [welltested.ai](https://welltested.ai) - Generate unit and integration tests using AI for mobile languages like Flutter within minutes. Free forever for developers.

[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

## Security and PKI

  * [alienvault.com](https://www.alienvault.com/open-threat-exchange/reputation-monitor) — Uncovers compromised systems in your network
  * [atomist.com](https://atomist.com/) — A quicker and more convenient way to automate various development tasks. Now in beta.
  * [Bridgecrew](https://bridgecrew.io/) — Infrastructure as code (IaC) security powered by the open source tool - [Checkov](https://github.com/bridgecrewio/checkov). The core Bridgecrew platform is free for up to 50 IaC resources.
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
  * [ringcaptcha.com](https://ringcaptcha.com/) — Tools to use the phone number as id, available for free
  * [seclookup.com](https://seclookup.com/) - Seclookup APIs can enrich domain threat indicators in SIEM, provide comprehensive information on domain names, and improve threat detection & response. Get 50K lookups free [here](https://account.seclookup.com/).
  * [snyk.io](https://snyk.io) — Can find and fix known security vulnerabilities in your open-source dependencies. Unlimited tests and remediation for open-source projects. Limited to 200 tests/month for your private projects.
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
  * [Virushee](https://virushee.com/) — Privacy-oriented file/data scanning powered by hybrid heuristic and AI-assisted engine. It is possible to use internal dynamic sandbox analysis. Limited to 50MB per file upload
  * [Escape GraphQL Quickscan](https://escape.tech/) - One-click security scan of your GraphQL endpoints. Free, no login required.
  * [HasMySecretLeaked](https://gitguardian.com/hasmysecretleaked) - Search across 20 million exposed secrets in public GitHub repositories, gists, issues,and comments for Free


[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

## Authentication, Authorization, and User Management

  * [Aserto](https://www.aserto.com) - Fine-grained authorization as a service for applications and APIs. Free up to 1000 MAUs and 100 authorizer instances.
  * [asgardeo.io](https://wso2.com/asgardeo) - Seamless Integration of SSO, MFA, passwordless auth and more. Includes SDKs for frontend and backend apps. Free up to 1000 MAUs and five identity providers.
  * [Auth0](https://auth0.com/) — Hosted SSO. Up to 7000 active users and two social identity providers.
  * [Authgear](https://www.authgear.com) - Bring Passwordless, OTPs, 2FA, SSO to your apps in minutes. All Front-end included. Free up to 5000 MAUs.
  * [Authress](https://authress.io/) — Authentication login and access control, unlimited identity providers for any project. Facebook, Google, Twitter and more. The first 1000 API calls are free.
  * [Authy](https://authy.com) - Two-factor authentication (2FA) on multiple devices, with backups. Drop-in replacement for Google Authenticator. Free for up to 100 successful authentications.
  * [Clerk](https://clerk.com) — User management, authentication, 2FA/MFA, prebuilt UI components for sign-in, sign-up, user profiles, and more. Free up to 10,000 monthly active users.
  * [Cloud-IAM](https://www.cloud-iam.com/) — Keycloak Identity and Access Management as a Service. Free up to 100 users and one realm.
  * [Corbado](https://www.corbado.com/) — Add passkey-first authentication to new or existing apps. Free for unlimited MAUs.
  * [Descope](https://www.descope.com/) — Highly customizable AuthN flows, has both a no-code and API/SDK approach, Free 7,500 active users/month, 50 tenants (up to 5 SAML/SSO tenants).
  * [duo.com](https://duo.com/) — Two-factor authentication (2FA) for website or app. Free for ten users, all authentication methods, unlimited, integrations, hardware tokens.
  * [Jumpcloud](https://jumpcloud.com/) — Provides directory as a service similar to Azure AD, user management, single sign-on, and RADIUS authentication. Free for up to 10 users.
  * [Kinde](https://kinde.com/) - Simple, robust authentication you can integrate with your product in minutes.  Everything you need to get started with 7,500 free MAU.
  * [logintc.com](https://www.logintc.com/) — Two-factor authentication (2FA) by push notifications, free for ten users, VPN, Websites, and SSH
  * [MojoAuth](https://mojoauth.com/) - MojoAuth makes it easy to implement Passwordless authentication on your web, mobile, or any application in minutes.
  * [Okta](https://developer.okta.com/signup/) — User management, authentication and authorization. Free for up to 100 monthly active users.
  * [onelogin.com](https://www.onelogin.com/) — Identity as a Service (IDaaS), Single Sign-On Identity Provider, Cloud SSO IdP, three company apps, and five personal apps, unlimited users
  * [Ory](https://ory.sh/) - AuthN/AuthZ/OAuth2.0/Zero Trust managed security platform. Forever free developer accounts with all security features, unlimited team members, 200 daily active users, and 25k/mo permission checks.
  * [Stytch](https://www.stytch.com/) - Flexible authentication APIs and SDKs with reach-resistant passwords, passwordless login flows, MFA, SSO, and more. Email/SMS sending + failover and fraud protections built-in. Offers 5,000 Monthly Active Users free (B2C) or 1,000 Monthly Active Users and 25 Organizations free (B2B).
  * [SuperTokens](https://supertokens.com/) - Open source user authentication that natively integrates into your app - enabling you to get started quickly while controlling the user and developer experience. Free for up to 5000 MAUs.
  * [Warrant](https://warrant.dev/) — Hosted enterprise-grade authorization and access control service for your apps. The free tier includes 1 million monthly API requests and 1,000 authz rules.
  * [ZITADEL Cloud](https://zitadel.com) — A turnkey user and access management that works for you and supports multi-tenant (B2B) use cases. Free for up to 25,000 authenticated requests, with all security features (no paywall for OTP, Passwordless, Policies, and so on).
  * [PropelAuth](https://propelauth.com) — A Sell to companies of any size immediately with a few lines of code, free up to 200 users and 10k Transactional Emails (with a watermark branding: "Powered by PropelAuth").
  * [Logto](https://logto.io/) - Develop, secure, and manage user identities of your product - for both authentication and authorization. Free for up to 5,000 MAUs with open-source self-hosted option available.


[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

## Mobile App Distribution and Feedback

* [TestApp.io](https://testapp.io) - Your go-to platform for ensuring your mobile apps work as they should. Free plan: one app, analytics, unlimited versions & installs, and feedback collection.
* [Diawi](https://www.diawi.com) - Deploy iOS & Android apps directly to devices. Free plan: app uploads, password-protected links, 1-day expiration, ten installations.
* [InstallOnAir](https://www.installonair.com) - Distribute iOS & Android apps over the air. Free plan: unlimited uploads, private links, 2-day expiration for guests, 60 days for registered users.
* [GetUpdraft](https://www.getupdraft.com) - Distribute mobile apps for testing. The free plan includes one app project, three app versions, 500 MB storage, and 100 app installations per month.
* [Appho.st](https://appho.st) - Mobile app hosting platform. The free plan includes five apps, 50 monthly downloads, and a maximum file size of 100 MB.

[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

## Management System

  * [bitnami.com](https://bitnami.com/) — Deploy prepared apps on IaaS. Management of 1 AWS micro instance free
  * [Esper](https://esper.io) — MDM and MAM for Android Devices with DevOps. One hundred devices free with one user license and 25 MB Application Storage.
  * [jamf.com](https://www.jamf.com/) —  Device management for iPads, iPhones, and Macs, three devices free
  * [Miradore](https://miradore.com) — Device Management service. Stay up-to-date with your device fleet and secure unlimited devices for free. The free plan offers basic features.
  * [moss.sh](https://moss.sh) - Help developers deploy and manage their web apps and servers. Free up to 25 git deployments per month
  * [runcloud.io](https://runcloud.io/) - Server management focusing mainly on PHP projects. Free for up to 1 server.
  * [ploi.io](https://ploi.io/) - Server management tool to easily manage and deploy your servers & sites. Free for one server.

[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

## Messaging and Streaming

  * [Ably](https://www.ably.com/) - Realtime messaging service with presence, persistence and guaranteed delivery. The free plan includes 3m messages per month, 100 peak connections, and 100 peak channels.
  * [cloudamqp.com](https://www.cloudamqp.com/) — RabbitMQ as a Service. Little Lemur plan: max 1 million messages/month, max 20 concurrent connections, max 100 queues, max 10,000 queued messages, multiple nodes in different AZ's
  * [connectycube.com](https://connectycube.com) - Unlimited chat messages, p2p voice & video calls, files attachments and push notifications. Free for apps up to 1000 users.
  * [courier.com](https://www.courier.com/) — Single API for push, in-app, email, chat, SMS, and other messaging channels with template management and other features. The free plan includes 10,000 messages/mo.
  * [HiveMQ](https://www.hivemq.com/mqtt-cloud-broker/) - Connect your MQTT devices to the Cloud Native IoT Messaging Broker.  Free to connect up to 100 devices (no credit card required) forever.
  * [knock.app](https://knock.app) – Notifications infrastructure for developers. Send to multiple channels like in-app, email, SMS, Slack, and push with a single API call. The free plan includes 10,000 messages/mo.
  * [NotificationAPI.com](https://www.notificationapi.com/) — Add user notifications to any software in 5 minutes. The free plan includes 10,000 notifications/month + 100 SMS and Automated Calls.
  * [pusher.com](https://pusher.com/) — Realtime messaging service. Free for up to 100 simultaneous connections and 200,000 messages/day
  * [scaledrone.com](https://www.scaledrone.com/) — Realtime messaging service. Free for up to 20 simultaneous connections and 100,000 events/day
  * [synadia.com](https://synadia.com/ngs) — [NATS.io](https://nats.io) as a service. Global, AWS, GCP, and Azure. Free forever with 4k msg size, 50 active connections, and 5GB of data per month.
  * [cloudkarafka.com](https://www.cloudkarafka.com/) - Free Shared Kafka cluster, up to 5 topics, 10MB data per topic and 28 days of data retention.
  * [pubnub.com](https://www.pubnub.com/) - Swift, Kotlin, and React messaging at 1 million transactions each month. Transactions may contain multiple messages.
  * [eyeson API](https://developers.eyeson.team/) - A video communication API service based on WebRTC (SFU, MCU) to build video platforms. Allows real-time data Injection, Video Layouts, Recordings, a fully featured hosted web UI (quickstart) or packages for custom UIs. Has a [free tier for developers](https://apiservice.eyeson.com/api-pricing) with 1000 meeting minutes a month.
  * [Upstash Kafka](https://upstash.com/kafka) - Serverless Kafka Cloud offering with per-request-pricing. It has a free tier with a maximum of 10,000 messages per day.
  * [webpushr](https://www.webpushr.com/) - Web Push Notifications - Free for upto 10k subscribers, unlimited push notifications, in-browser messaging
  * [Scramjet Cloud Platform Beta](https://www.scramjet.org/#join-beta) - An end-to-end stream processing platform in free beta and offering 15 petabyte-seconds of free compute after the beta ends.
  * [httpSMS](https://httpsms.com) - Send and receive text messages using your Android phone as an SMS Gateway. Free to send and receive up to 200 messages per month.

[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

## Log Management

  * [bugfender.com](https://bugfender.com/) — Free up to 100k log lines/day with 24 hours retention
  * [logentries.com](https://logentries.com/) — Free up to 5 GB/month with seven days retention
  * [loggly.com](https://www.loggly.com/) — Free for a single user, 200MB/day with seven days retention
  * [logz.io](https://logz.io/) — Free up to 1 GB/day, one day retention
  * [ManageEngine Log360 Cloud](https://www.manageengine.com/cloud-log-management) — Log Management service powered by Manage Engine. Free Plan offers 50 GB storage with 1 Month retention.
  * [papertrailapp.com](https://papertrailapp.com/) — 48 hours search, seven days archive, 50 MB/month
  * [sematext.com](https://sematext.com/logsene) — Free up to 500 MB/day, seven days retention
  * [sumologic.com](https://www.sumologic.com/) — Free up to 500 MB/day, seven days retention
  * [logflare.app](https://logflare.app/) — Free for up to 12,960,000 entries per app per month, 3 days retention
  * [logtail.com](https://logtail.com/) — ClickHouse-based SQL-compatible log management. Free up to 1 GB per month, three days retention.
  * [logzab.com](https://logzab.com/) — Audit trail management system. Free 1,000 user activity logs per month, 1-month retention, for up to 5 projects.

[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

## Translation Management

  * [crowdin.com](https://crowdin.com/) — Unlimited projects, unlimited strings, and collaborators for Open Source
  * [gitlocalize.com](https://gitlocalize.com) - Free and unlimited for both private and public repositories
  * [Lecto](https://lecto.ai/) - Machine Translation API with Free tier (30 free requests, 1000 translated characters per request). Integrated with the Loco Translate Wordpress plugin.
  * [lingohub.com](https://lingohub.com/) — Free up to 3 users, always free for Open Source
  * [localazy.com](https://localazy.com) - Free for 1000 source language strings, unlimited languages, unlimited contributors, startup and open source deals
  * [Localeum](https://localeum.com) - Free up to 1000 strings, one user, unlimited languages, unlimited projects
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

[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

## Monitoring

  * [Pingmeter.com](https://pingmeter.com/) - 5 uptime monitors with 10-minute interval. Monitor SSH, HTTP, HTTPS, and any custom TCP ports.
  * [appdynamics.com](https://www.appdynamics.com/) — Free for 24-hour metrics, application performance management agents limited to one Java, one .NET, one PHP, and one Node.js
  * [appneta.com](https://www.appneta.com/) — Free with 1-hour data retention
  * [appspector.com](https://appspector.com/) - Mission control for remote iOS/Android/Flutter debugging. Free for small traffic usage (64MB of logs).
  * [assertible.com](https://assertible.com) — Automated API testing and monitoring. Free plans for teams and individuals.
  * [bleemeo.com](https://bleemeo.com) - Free for 3 servers, 5 uptime monitors, unlimited users, unlimited dashboards, unlimited alerting rules.
  * [checklyhq.com](https://checklyhq.com) - Open source E2E / Synthetic monitoring and deep API monitoring for developers. Free plan with five users and 50k+ check runs.
  * [circonus.com](https://www.circonus.com/) — Free for 20 metrics
  * [cloudsploit.com](https://cloudsploit.com) — AWS security and configuration monitoring. Free: unlimited on-demand scans, unlimited users, unlimited stored accounts. Subscription: automated scanning, API access, etc.
  * [cronitor.io](https://cronitor.io/) - Performance insights and uptime monitoring for cron jobs, websites, APIs and more. A free tier with five monitors.
  * [datadoghq.com](https://www.datadoghq.com/) — Free for up to 5 nodes
  * [deadmanssnitch.com](https://deadmanssnitch.com/) — Monitoring for cron jobs. One free snitch (monitor), more if you refer others to sign up
  * [downtimemonkey.com](https://downtimemonkey.com/) — 60 uptime monitors, 5-minute interval. Email, Slack alerts.
  * [economize.cloud](https://economize.cloud) — Economize helps demystify cloud infrastructure costs by organizing cloud resources to optimize and report the same. Free for up to $5,000 spent on Google Cloud Platform every month.
  * [elastic.co](https://www.elastic.co/solutions/apm) — Instant performance insights for JS developers. Free with 24-hour data retention
  * [freeboard.io](https://freeboard.io/) — Free for public projects. Dashboards for your Internet of Things (IoT) projects
  * [Grafana Cloud](https://grafana.com/products/cloud/) - Grafana Cloud is a composable observability platform that integrates metrics and logs with Grafana. Free: 3 users, ten dashboards, 100 alerts, metrics storage in Prometheus and Graphite (10,000 series, 14 days retention), logs storage in Loki (50 GB of logs, 14 days retention)
  * [healthchecks.io](https://healthchecks.io) — Monitor your cron jobs and background tasks. Free for up to 20 checks.
  * [inspector.dev](https://www.inspector.dev) - A complete Real-Time monitoring dashboard in less than one minute with a free forever tier.
  * [instrumentalapp.com](https://instrumentalapp.com) - Beautiful and easy-to-use application and server monitoring with up to 500 metrics and 3 hours of data visibility for free
  * [keychest.net/speedtest](https://keychest.net/speedtest) - Independent speed test and TLS handshake latency test against Digital Ocean
  * [letsmonitor.org](https://letsmonitor.org) - SSL monitoring, free for up to 5 monitors
  * [loader.io](https://loader.io/) — Free load testing tools with limitations
  * [meercode.io](https://meercode.io/) — Meercode is the ultimate monitoring dashboard for your CI/CD builds. Free for open-source and one private repository.
  * [netdata.cloud](https://www.netdata.cloud/) — Netdata is an open-source tool to collect real-time metrics. It's a growing product and can also be found on GitHub!
  * [newrelic.com](https://www.newrelic.com) — New Relic observability platform built to help engineers create more perfect software. From monoliths to serverless, you can instrument everything and then analyze, troubleshoot, and optimize your entire software stack. The free tier offers 100GB/month of free data ingest, one free full-access user, and unlimited free primary users.
  * [Middleware.io](https://middleware.io/) -  Middleware observability platform provides complete visibility into your apps & stack, so you can monitor & diagnose issues at scale. They have a free forever plan for Dev community use that allows Log monitoring for up to 1M log events, Infrastructure monitoring & APM for up to 2 hosts.
  * [nixstats.com](https://nixstats.com) - Free for one server. E-Mail Notifications, public status page, 60-second interval, and more.
  * [OnlineOrNot.com](https://onlineornot.com/) - OnlineOrNot provides uptime monitoring for websites and APIs, monitoring for cron jobs and scheduled tasks. Also provides status pages. The first five checks with a 3-minute interval are free. The free tier sends alerts via Slack, Discord, and Email.
  * [opsgenie.com](https://www.opsgenie.com/) — Powerful alerting and on-call management for operating always-on services. Free up to 5 users.
  * [paessler.com](https://www.paessler.com/) — Powerful infrastructure and network monitoring solution, including alerting, strong visualization capabilities, and basic reporting. Free up to 100 sensors.
  * [pagecrawl.io](https://pagecrawl.io/) -  Monitor website changes, free for up to 6 monitors with daily checks.
  * [syagent.com](https://syagent.com/) — Noncommercial free server monitoring service, alerts and metrics.
  * [pagerly.io](https://pagerly.io/) -  Manage on-calls on Slack  (integrates with Pagerduty, OpsGenie). Free up to 1 team (one team refers to one on call)
  * [pagertree.com](https://pagertree.com/) - Simple interface for alerting and on-call management. Free up to 5 users.
  * [pingbreak.com](https://pingbreak.com/) — Modern uptime monitoring service. Check unlimited URLs and get downtime notifications via Discord, Slack, or email.
  * [pingpong.one](https://pingpong.one/) — Advanced status page platform with monitoring. The free tier includes one public customizable status page with an SSL subdomain. Pro plan is offered to open-source projects and non-profits free of charge.
  * [robusta.dev](https://home.robusta.dev/) — Powerful Kubernetes monitoring based on Prometheus. Bring your own Prometheus or install the all-in-one bundle. The free tier includes up to 20 Kubernetes nodes. Alerts via Slack, Microsoft Teams, Discord, and more. Integrations with PagerDuty, OpsGenie, VictorOps, DataDog, and many other tools.
  * [sematext.com](https://sematext.com/) — Free for 24-hour metrics, unlimited servers, ten custom metrics, 500,000 custom metrics data points, unlimited dashboards, users, etc.
  * [sitemonki.com](https://sitemonki.com/) — Website, domain, Cron & SSL monitoring, 5 monitors in each category for free
  * [sitesure.net](https://sitesure.net) - Website and cron monitoring - 2 monitors free
  * [skylight.io](https://www.skylight.io/) — Free for first 100,000 requests (Rails only)
  * [speedchecker.xyz](https://probeapi.speedchecker.xyz/) — Performance Monitoring API, checks Ping, DNS, etc.
  * [stathat.com](https://www.stathat.com/) — Get started with ten stats for free, no expiration
  * [statuscake.com](https://www.statuscake.com/) — Website monitoring, unlimited tests free with limitations
  * [statusgator.com](https://statusgator.com/) — Status page monitoring, 3 monitors free
  * [thousandeyes.com](https://www.thousandeyes.com/) — Network and user experience monitoring. 3 locations and 20 data feeds of major web services free
  * [uptimerobot.com](https://uptimerobot.com/) — Website monitoring, 50 monitors free
  * [uptimetoolbox.com](https://uptimetoolbox.com/) — Free monitoring for five websites, 60-second intervals, public statuspage.
  * [zenduty.com](https://www.zenduty.com/) — End-to-end incident management, alerting, on-call management, and response orchestration platform for network operations, site reliability engineering, and DevOps teams. Free for up to 5 users.
  * [instatus.com](https://instatus.com) - Get a beautiful status page in 10 seconds. Free forever with unlimited subs and unlimited teams.
  * [Squadcast.com](https://squadcast.com) - Squadcast is an end-to-end incident management software designed to help you promote SRE best practices. Free forever plan available for up to 10 users.
  * [RoboMiri.com](https://robomiri.com/) - RoboMiri is a stable uptime monitor that offers a wide range of monitors: cronjob, keyword, website, port, ping. Twenty-five uptime checks with 3-minute interval checks for free. Alerts via Phone Call, SMS, Email, and Webhooks.
  * [Better Stack](https://betterstack.com/better-uptime) - Uptime monitoring, incident management, on-call scheduling/alerting, and status pages in a single product. The free plan includes ten monitors with 3-minute check frequency and status pages.
  * [Pulsetic](https://pulsetic.com) - 10 monitors, 6 Months of historical Uptime/Logs, unlimited status pages, and custom domains included! For infinite time and unlimited email alerts for free. You don't need a credit card.
  * [Wachete](https://www.wachete.com) - monitor five pages, checks every 24 hours.
  * [Xitoring.com](https://xitoring.com/) — Uptime monitoring: 20 free, Linux and Windows Server monitoring: 5 free, Status page: 1 free - Mobile app, multiple notification channel, and much more!

[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

## Crash and Exception Handling

  * [CatchJS.com](https://catchjs.com/) - JavaScript error tracking with screenshots and click trails. Free for open-source projects.
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

[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

## Search

  * [algolia.com](https://www.algolia.com/) — Hosted search solution with typo-tolerance, relevance, and UI libraries to easily create search experiences. The free "Build" plan includes 1M documents and 10K searches/month. Also offers [developer documentation search](https://docsearch.algolia.com/) for free.
  * [bonsai.io](https://bonsai.io/) — Free 1 GB memory and 1 GB storage
  * [CommandBar](https://www.commandbar.com/) - Unified Search Bar as-a-service, web-based UI widget/plugin that allows your users to search contents, navigations, features, etc. within your product, which helps discoverability. Free for up to 1,000 Monthly Active Users, unlimited commands.
  * [Magny](https://magny.io) - SaaS service that helps implement command palettes (e.g. in-app search), which significantly decreases the time users find anything in an app, leveraging the user experience and efficiency.
  * [searchly.com](http://www.searchly.com/) — Free 2 indices and 20 MB storage
  * [pagedart.com](https://pagedart.com/) - AI search as a service the free tier includes 1,000 Documents and 50,000 searches. Larger free decks are possible for worthwhile projects.

[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

## Education and Career Development

  * [FreeCodeCamp](https://www.freecodecamp.org/) - Open-source platform offering free courses and certifications in Data Analysis, Information Security, Web Development, and more.
  * [The Odin Project](https://www.theodinproject.com/) - Free, open-source platform with a curriculum focused on JavaScript and Ruby for web development.

[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

## Email

  * [10minutemail](https://10minutemail.com) - Free, temporary email for testing.
  * [AnonAddy](https://anonaddy.com) - Open-source anonymous email forwarding, create unlimited email aliases for free
  * [Antideo](https://www.antideo.com) — 10 API requests per hour for email verification, IP, and phone number validation in the free tier. No Credit Cards are required.
  * [Brevo](https://www.brevo.com/) — 9,000 emails/month, 300 emails/day free
  * [Bump](https://bump.email/) - Free 10 Bump email addresses, one custom domain
  * [Burnermail](https://burnermail.io/) – Free 5 Burner Email Addresses, 1 Mailbox, 7-day Mailbox History
  * [Buttondown](https://buttondown.email/) — Newsletter service. Up to 100 subscribers free
  * [CloudMailin](https://www.cloudmailin.com/) - Incoming email via HTTP POST and transactional outbound - 10,000 free emails/month
  * [cloudmersive.com](https://www.cloudmersive.com/email-verification-api) — Email validation and verification API for developers, 800 free API requests/month
  * [Contact.do](https://contact.do/) — Contact form in a link (bitly for contact forms)
  * [debugmail.io](https://debugmail.io/) — Easy to use testing mail server for developers
  * [DNSExit](https://dnsexit.com/) - Up to 2 Email addresses under your domain for free with 100MB of storage space. IMAP, POP3, SMTP, SPF/DKIM support.
  * [emaildrop.io](https://emaildrop.io/) — Free disposable email provider. Email addresses can be created via GraphQL API.
  * [EmailLabs.io](https://emaillabs.io/en) — Send up to 9,000 Emails for free every month, up to 300 emails daily.
  * [EmailOctopus](https://emailoctopus.com) - Up to 2,500 subscribers and 10,000 emails per month free
  * [EmailJS](https://www.emailjs.com/) – This is not an entire email server; this is just an email client that you can use to send emails right from the client without exposing your credentials, the free tier has 200 monthly requests, 2 email templates, Requests up to 50Kb, Limited contacts history.
  * [EtherealMail](https://ethereal.email) - Ethereal is a fake SMTP service, mainly aimed at Nodemailer and EmailEngine users (but not limited to). It's an entirely free anti-transactional email service where messages never get delivered.
  * [Tempmailers](https://tempmailers.com/) - Generate unlimited temporary email addresses for free
  * [Emailvalidation.io](https://emailvalidation.io) - 100 free email verifications per month
  * [fakermail.com](https://fakermail.com/) — Free, temporary email for testing with the last 100 email accounts stored.
  * [forwardemail.net](https://forwardemail.net) — Free email forwarding for custom domains. Create and forward an unlimited amount of email addresses with your domain name (**note**: You must pay if you use .casa, .cf, .click, .email, .fit, .ga, .gdn, .gq, .lat, .loan, .london, .men, .ml, .pl, .rest, .ru, .tk, .top, .work TLDs due to spam)
  * [HotTempMail](https://hottempmail.com/) - Unlimited, free, disposable temporary email addresses. Autoexpires in one day.
  * [Imitate Email](https://imitate.email) - Sandbox Email Server for testing email functionality across build/qa and ci/cd. Free accounts get 15 emails a day forever.
  * [ImprovMX](https://improvmx.com) – Free email forwarding.
  * [EForw](https://www.eforw.com) – Free email forwarding for one domain. Receive and send emails from your domain.
  * [inboxkitten.com](https://inboxkitten.com/) - Free temporary/disposable email inbox, with up to 3-day email auto-deletes. Open source and can be self-hosted.
  * [mail-tester.com](https://www.mail-tester.com) — Test if the email's DNS/SPF/DKIM/DMARC settings are correct, 20 free/month.
  * [dkimvalidator.com](https://dkimvalidator.com/) - Test if the email's DNS/SPF/DKIM/DMARC settings are correct, free service by roundsphere.com
  * [mailcatcher.me](https://mailcatcher.me/) — Catches mail and serves it through a web interface.
  * [Mailcheck.ai](https://www.mailcheck.ai/) - Prevent users to sign up with temporary email addresses, 120 requests/hour (~86,400 per month)
  * [Mailchimp](https://mailchimp.com/) — 500 subscribers and 1,000 emails/month free.
  * [MailerLite.com](https://www.mailerlite.com) — 1,000 subscribers/month, 12,000 emails/month free
  * [MailerSend.com](https://www.mailersend.com) — Email API, SMTP, 3,000 emails/month free for transactional emails
  * [mailinator.com](https://www.mailinator.com/) — Free, public email system where you can use any inbox you want
  * [Mailjet](https://www.mailjet.com/) — 6,000 emails/month free (200 emails daily sending limit)
  * [Mailnesia](https://mailnesia.com) - Free temporary/disposable email, which auto visit registration link.
  * [mailsac.com](https://mailsac.com) - Free API for temporary email testing, free public email hosting, outbound capture, email-to-slack/websocket/webhook (1,500 monthly API limit)
  * [Mailtie.com](https://mailtie.com/) - Free Email Forwarding for Your Domain. You don't need to register. Free Forever.
  * [Mailtrap.io](https://mailtrap.io/) — Fake SMTP server for development, free plan with one inbox, 100 messages, no team member, two emails/second, no forward rules.
  * [Mailvalidator.io](https://mailvalidator.io/) - Verify 300 emails/month for free, real-time API with bulk processing available.
  * [Mail7.io](https://www.mail7.io/) — Free Temp Email Addresses for QA Developers. Create email addresses instantly using Web Interface or API.
  * [Mutant Mail](https://www.mutantmail.com/) – Free 10 Email IDs, 1 Domain, 1 Mailbox. Single Mailbox for All Email IDs.
  * [Outlook.com](https://outlook.live.com/owa/) - Free personal email and calendar.
  * [Parsio.io](https://parsio.io) — Free email parser (Forward email, extract the data, send it to your server)
  * [pepipost.com](https://pepipost.com) — 30k emails free for the first month, then the first 100 emails/day free.
  * [Postmark](https://postmarkapp.com/) - 100 emails/month free, unlimited DMARC weekly digests.
  * [Proton Mail](https://proton.me/mail) -  Free secure email account service provider with built-in end-to-end encryption. Free 1GB storage.
  * [Queuemail.dev](https://queuemail.dev) — Reliable email delivery API. Free tier (10,000 emails/per month). Send asynchronously. Use several SMTP servers. Blocklists, Logging, Tracking, Webhooks, and more.
  * [QuickEmailVerification](https://quickemailverification.com) — Verify 100 emails daily for free on a free tier along with other free APIs like DEA Detector, DNS Lookup, SPF Detector, and more.
  * [Resend](https://resend.com) - Transactional emails API for developers. 3,000 emails/month, 100 emails/day free, one custom domain.
  * [Sender](https://www.sender.net) Up to 15,000 emails/month, up to 2,500 subscribers
  * [SendGrid](https://sendgrid.com/) — 100 emails/day and 2,000 contacts free
  * [Sendpulse](https://sendpulse.com) — 500 subscribers/month, 15,000 emails/month free
  * [SimpleLogin](https://simplelogin.io/) – Open source, self-hostable email alias/forwarding solution. Free 5 Aliases, unlimited bandwidth, unlimited reply/send. Free for educational staff (student, researcher, etc.).
  * [Substack](https://substack.com) — Unlimited free newsletter service. Start paying when you charge for it.
  * [Tempmailo](https://tempmailo.com/) - Unlimited free temp email addresses. Autoexpire in two days.
  * [Takeout](https://takeout.bysourfruit.com) - A constantly updated email service that makes sending emails easy. Five hundred transactional emails/month free.
  * [temp-mail.io](https://temp-mail.io) — Free disposable temporary email service with multiple emails at once and forwarding
  * [tinyletter.com](https://tinyletter.com/) — 5,000 subscribers/month free
  * [trashmail.com](https://www.trashmail.com) - Free disposable email addresses with forwarding and automatic address expiration
  * [Tutanota](https://tutanota.com/) - Free secure email account service provider with built-in end-to-end encryption, no ads, no tracking. Free 1GB storage. Which is also partially [open source](https://github.com/tutao/tutanota), so you can self-host.
  * [validemail.io](https://validemail.io/) - Free Tier with 10,000 validations per month & 10 requests per second.
  * [Verifalia](https://verifalia.com/email-verification-api) — Real-time email verification API with mailbox confirmation and disposable email address detector; 25 free email verifications/day.
  * [verimail.io](https://verimail.io/) — Bulk and API email verification service. 100 free verifications/month
  * [Zoho](https://www.zoho.com) — Started as an e-mail provider but now provides a suite of services, some of which have free plans. List of services having free plans :
     - [Email](https://zoho.com/mail) Free for 5 users. 5GB/user & 25 MB attachment limit, one domain.
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
     - [Campaigns](https://zoho.com/campaigns)
     - [Forms](https://zoho.com/forms)
     - [Sign](https://zoho.com/sign)
     - [Surveys](https://zoho.com/surveys)
     - [Bookings](https://zoho.com/bookings)
     - [Analytics](https://zoho.com/analytics)

[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

## Feature Toggles Management Platforms

  * [ConfigCat](https://configcat.com) - ConfigCat is a developer-centric feature flag service with unlimited team size, excellent support, and a reasonable price tag. Free plan up to 10 flags, two environments, 1 product, and 5 Million requests per month.
  * [Flagsmith](https://flagsmith.com) - Release features with confidence; manage feature flags across web, mobile, and server-side applications. Use our hosted API, deploy to your own private cloud, or run on-premise.
  * [GrowthBook](https://growthbook.io) - Open source feature flag and A/B testing provider with built-in Bayesian statistical analysis engine. Free for up to 3 users, unlimited feature flags and experiments.
  * [Molasses](https://www.molasses.app) - Powerful feature flags and A/B testing. Free up to 3 environments with five feature flags each.
  * [Toggled.dev](https://www.toggled.dev) - Enterprise-ready, scalable multi-regional feature toggles management platform. Free plan up to 10 flags, two environments, unlimited requests. SDK, analytics dashboard, release calendar, Slack notifications, and all other features are included in the endless free plan.

[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

## Font

  * [dafont](https://www.dafont.com/) - The fonts presented on this website are their authors' property and are either freeware, shareware, demo versions, or public domain.
  * [Everything Fonts](https://everythingfonts.com/) - Offers multiple tools; @font-face, Units Converter, Font Hinter and Font Submitter.
  * [Font Squirrel](https://www.fontsquirrel.com/) - Freeware fonts licensed for commercial work. Hand-selected these typefaces and presented them in an easy-to-use format.
  * [Google Fonts](https://fonts.google.com/) - Many free fonts are easy and quick to install on a website via a download or a link to Google's CDN.
  * [FontGet](https://www.fontget.com/) - Has a variety of fonts available to download and sorted neatly with tags.
  * [Fontshare](https://www.fontshare.com/) - is a free fonts service. It’s a growing collection of professional-grade fonts, 100% free for personal and commercial use.
  * [Befonts](https://befonts.com/) - Provides several unique fonts for personal or commercial use.
  * [Font of web](https://fontofweb.com/) - Identify all the fonts used on a website and how they are used.
  * [Bunny](https://bunny.net)
    * [Bunny Fonts](https://fonts.bunny.net/) - All the Google Fonts with Google Fonts drop-in compatible API. Privacy oriented!
    * [Bunny DNS](https://bunny.net/dns/) - DNS hosting, 20 million free queries
  * [FontsKey](https://www.fontskey.com/) - Provides free and commercial paid fonts for personal use and can enter text for quick filtering.

[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

## Forms

  * [Form2Channel](https://form2channel.com) - Send form submissions to Google Sheets, Email, Email, Slack, Telegram or Webhooks. Unlimited and free. Features include multiple recipients, custom thank-you pages, file uploads, and more.
  * [Feathery](https://feathery.io) - Powerful, developer-friendly form builder. Build signup & login, user onboarding, payment flows, complex financial applications, and more. The free plan allows up to 250 submissions/month and five active forms.
  * [Form-Data](https://form-data.com) - No-code forms backend. Spam filter, email notification and auto-respond, webhooks, zapier, redirects, AJAX or POST, and more. The free plan offers unlimited forms, 20 submissions/month, and an additional 2000 submissions with Form-Data badge.
  * [FabForm](https://fabform.io/) - Form backend platform for intelligent developers. The free plan allows 250 form submissions per month. Friendly modern GUI. Integrates with Google Sheets, Airtable, Slack, Email, and others.
  * [Form.taxi](https://form.taxi/) — Endpoint for HTML forms submissions. With notifications, spam blockers, and GDPR-compliant data processing. Free plan for basic usage.
  * [Formcake.com](https://formcake.com) - Form backend for devs, free plan allows unlimited forms, 100 submissions, Zapier integration. No libraries or dependencies are required.
  * [Formcarry.com](https://formcarry.com) - HTTP POST Form endpoint, Free plan allows 100 monthly submissions.
  * [formingo.co](https://www.formingo.co/)- Easy HTML forms for static websites. You can start for free without registering an account. The free plan allows 500 monthly submissions and a customizable reply-to email address.
  * [FormKeep.com](https://www.formkeep.com/) - Unlimited forms with 50 monthly submissions, spam protection, email notification, and a drag-and-drop designer that can export HTML. Additional features include custom field rules, teams, and integrations to Google Sheets, Slack, ActiveCampaign, and Zapier.
  * [formlets.com](https://formlets.com/) — Online forms, unlimited single page forms/month, 100 submissions/month, email notifications.
  * [formspark.io](https://formspark.io/) -  Form to Email service, free plan allows unlimited forms, 250 submissions per month, support by Customer assistance team.
  * [Formspree.io](https://formspree.io/) — Send email using an HTTP POST request. The free tier limits to 50 submissions per form per month.
  * [Formsubmit.co](https://formsubmit.co/) — Easy form endpoints for your HTML forms. Free Forever. No registration is required.
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
  * [staticforms.xyz](https://www.staticforms.xyz/) - Integrate HTML forms easily without any server-side code for free. After the user submits the form, an email with the form content will be sent to your registered address.
  * [stepFORM.io](https://stepform.io) - Quiz and Form Builder. The free plan has five forms, up to 3 steps per form, and 50 monthly responses.
  * [Tapform.com](https://tapform.com/) — Includes unlimited forms, unlimited fields, and unlimited submissions for free. Forms can either be displayed in a standard or a chat format.
  * [Typeform.com](https://www.typeform.com/) — Include beautifully designed forms on websites.  The free plan allows only ten fields per form and 100 monthly responses.
  * [WaiverStevie.com](https://waiverstevie.com) - Electronic Signature platform with a REST API. You can receive notifications with webhooks. Free plan watermarks signed documents but allow unlimited envelopes + signatures.
  * [Web3Forms](https://web3forms.com) - Contact forms for Static & JAMStack Websites without writing backend code. The free plan allows Unlimited Forms, Unlimited Domains & 250 Submissions per month.
  * [WebAsk](https://webask.io) - Survey and Form Builder. The free plan has three surveys per account, 100 monthly responses, and ten elements per survey.
  * [Wufoo](https://www.wufoo.com/) - Quick forms to use on websites. The free plan has a limit of 100 submissions each month.
  * [formpost.app](https://formpost.app) - Free, unlimited Form to Email service. Set up custom redirects, auto-response, webhooks, etc. for free.
  * [Formester.com](https://formester.com) - Share and embed unique-looking forms on your website—no limits on the number of forms created or features restricted by the plan. Get up to 100 submissions every month for free.
  * [SimplePDF.eu](https://simplepdf.eu/embed) - Embed a PDF editor on your website and turn any PDF into a fillable form. The free plan allows unlimited PDFs with three submissions per PDF.
  * [forms.app](https://forms.app/) — Create online forms with powerful features like conditional logic, automatic score calculator, and AI. Collect up to 100 responses with a free plan, embed your forms on a website, or use them with a link.
  * [Qualli](https://usequalli.com) - In App Surveys, designed for mobile. Use Qualli AI to craft the perfect questions. You can try it out on our free plan, up to 500 MAU, create unlimited forms and triggers.
  * [Sprig](https://sprig.com/) - 1 In-Product Survey or Survey with Replay per month, with GPT-powered AI Analysis.
  * [feedback.fish](https://feedback.fish/) - Free plan allows collecting 25 total feedback submissions. Easy to integrate with React and Vue components provided.

[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

## Generative AI

* [Portkey](https://portkey.ai/) - Control panel for Gen AI apps featuring an observability suite & an AI gateway. Send & log up to 10,000 requests for free every month.
* [OpenPipe](https://openpipe.ai) - Fully managed fine-tuning for developers. Free plan lets you fine-tune one model with upto 2,000 rows per dataset.
* [Braintrust](https://www.braintrustdata.com/) - Evals, prompt playground, and data management for Gen AI. Free plan gives upto 1,000 private eval rows/week.
* [Findr](https://www.usefindr.com/) - Universal search that lets you search all your apps, at once. Search assistant that lets you answer questions using your information. Free plan offers unlimited unified search and 5 co daily co pilot queries.

[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

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
  * [Gcore](https://gcorelabs.com/)
    * [CDN](https://gcorelabs.com/cdn/) — Global content delivery network, 1 TB and 1 million requests per month free.
    * [DNS Hosting](https://gcorelabs.com/dns/) — Free DNS hosting.
  * [LightCDN](https://www.lightcdn.com) - Free 100GB CDN with eight international Pop. Unlimited HTTP(S) requests.
  * [CacheFly](https://portal.cachefly.com/signup/free2023) - Up to 5 TB per month of Free CDN traffic, 19 Core PoPs , 1 Domain and Universal SSL.

[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

## PaaS

  * [anvil.works](https://anvil.works) - Web app development with nothing but Python. Free tier with unlimited apps and 30-second timeouts.
  * [configure.it](https://www.configure.it/) — Mobile app development platform, free for two projects, limited features but no resource limits
  * [codenameone.com](https://www.codenameone.com/) — Open source, cross-platform, mobile app development toolchain for Java/Kotlin developers. Free for commercial use with an unlimited number of projects
  * [Cosmonic](https://cosmonic.com) - Feature-rich WebAssembly PaaS and SDKs for low boilerplate, flexible, and secure by default microservices. Always free tier includes a managed host, 25 microservices, and capabilities like a robust key-value store, load-balanced public HTTP endpoints, and more.
  * [Cyclic](https://www.cyclic.sh) - Fullstack app hosting - Push to GitHub to build and deploy Javascript/Node.js apps. Includes: Authentication, Cron jobs, Custom Domains, Database, Storage, and Streaming logs. Paid plans include branch-based environments, multi-regional deployments, and increased limits.
  * [deco.cx](https://www.deco.cx/en/dev) - Edge-native frontend platform with a visual CMS auto-generated from TypeScript code. Built-in A/B testing, content segmentation, and real-time analytics. Perfect for content-heavy and Enterprise e-commerce websites. Free up to 5k pageviews/month or open-source/personal projects.
  * [Deno Deploy](https://deno.com/deploy) - Distributed system that runs JavaScript, TypeScript, and WebAssembly at the edge worldwide. The free tier includes 100,000 requests per day and 100 GiB data transfers per month.
  * [domcloud.co](https://domcloud.co) – Linux hosting service that provides CI/CD with GitHub, SSH, and MariaDB/Postgres database. The free version has 1 GB storage and 1 GB network/month limit and is limited to a free domain.
  * [encore.dev](https://encore.dev/) — Backend framework using static analysis to provide automatic infrastructure, boilerplate-free code, and more. Includes free cloud hosting for hobby projects.
  * [flightcontrol.dev](https://flightcontrol.dev/) - Deploy web services, databases, and more on your own AWS account with a Git push style workflow. Free tier for users with 1 developer on personal GitHub repos. AWS costs are billed through AWS, but you can use credits and the AWS free tier.
  * [gigalixir.com](https://gigalixir.com/) - Gigalixir provides one free instance that never sleeps and a free-tier PostgreSQL database limited to 2 connections, 10, 000 rows and no backups for Elixir/Phoenix apps.
  * [Glitch](https://glitch.com/) — Free public hosting with code sharing and real-time collaboration features. The free plan has a 1000-hours/month limit.
  * [Hop](https://hop.io/) — Web services hosting platform without configs. Free tier with 1x Shared CPU, 512MB RAM and 3GB Storage.
  * [Mendix](https://www.mendix.com/) — Rapid Application Development for Enterprises, unlimited accessible sandbox environments supporting total users, 0.5 GB storage and 1 GB RAM per app. Also, Studio and Studio Pro IDEs are allowed in the free tier.
  * [m3o.com](https://m3o.com) - A cloud platform for API services development. M3O is a fully managed Micro as a Service offering focusing on Go microservices development in the Cloud. The free tier provides enough to run five services and collaborate with others.
  * [pipedream.com](https://pipedream.com) - An integration platform built for developers. Develop any workflow based on any trigger. Workflows are code you can run [for free](https://docs.pipedream.com/pricing/). No server or cloud resources to manage.
  * [pythonanywhere.com](https://www.pythonanywhere.com/) — Cloud Python app hosting. Beginner account is free, 1 Python web application at your-username.pythonanywhere.com domain, 512 MB private file storage, one MySQL database
  * [Serverless Cloud](https://www.serverless.com/cloud) - Serverless Cloud lets you build Serverless APIs, DBs, and Storage by using infrastructure _from_ the code approach(no YAML, no infrastructure configuration). Serverless Inc. provides the product and it is currently under public preview.
  * [fly.io](https://fly.io/) - Fly is a platform for applications that must run globally. It runs your code close to users and scales compute in cities where your app is busiest. Write your code, package it into a Docker image, deploy it to Fly's platform, and let that do all the work to keep your app snappy. Free allowances include up to 3 shared-CPU-1x 256mb VMs, 3GB persistent volume storage (total), and 160GB outbound data transfer.
  * [Divio](https://www.divio.com/) - A platform to manage cloud applications deploying only using Docker. Available free subscription for development projects. Requires card and no custom domain support.
  * [Koyeb](https://www.koyeb.com) - Koyeb is a developer-friendly serverless platform to deploy apps globally. Seamlessly run Docker containers, web apps, and APIs with git-based deployment, native autoscaling, a global edge network, and built-in service mesh and discovery. Free Instance lets you deploy a web service in Frankfurt, Germany or Washington, D.C., US. Free Managed Postgres database available in Frankfurt (Germany), Washington, D.C. (US), and Singapore. 1GB memory, 1GB storage, and 0.25 CPU. No credit card is required to get started.
  * [Napkin](https://www.napkin.io/) - FaaS with 500Mb of memory, a default timeout of 15 seconds, and 5,000 free API calls/month rate-limited to 5 calls/second.
  * [Meteor Cloud](https://www.meteor.com/cloud) — Galaxy hosting. Meteor's platform-as-a-service for Meteor apps includes free MongoDB Shared Hosting and automatic SSL.
  * [Northflank](https://northflank.com) — Build and deploy microservices, jobs, and managed databases with a powerful UI, API & CLI. Seamlessly scale containers from version control and external Docker registries. The free tier includes two services, two cron jobs and 1 database.
  * [Platformatic Cloud](https://platformatic.dev/) - Platformatic offers many open-source packages to wrap and deploy your Fastify application in the Platformatic Cloud. Built-in CD with a GitHub Action. [Free plan](https://platformatic.dev/pricing/) for hobbyists with a simple [GitHub login](https://platformatic.cloud/).
  * [YepCode](https://yepcode.io) - All-in-one platform to connect APIs and services in a serverless environment. It brings all the agility and benefits of NoCode tools but with all the power of using programming languages. The free tier includes [1.000 yeps](https://yepcode.io/pricing/).
  * [WunderGraph](https://cloud.wundergraph.com) - An open-source platform that allows you to  quickly build, ship and manage modern APIs. Built-in CI/CD, GitHub integration, and automatic HTTPS. Up to 3 projects, 1GB egress, 300 minutes of build time per month on the [free plan](https://wundergraph.com/pricing)
  * [Doprax Cloud](https://www.doprax.com) — Cloud hosting for your Apps, Websites and APIs. Free for one app, with 4 * 256MB RAM and 2 GB of disk. You must have at least $3 in your account credit balance to create an app space.
  * [Zeabur](https://zeabur.com) - Deploy your services with one click. Free for three services, with US$ 5 free credits per month.
  * [mogenius](https://mogenius.com) - Easily build, deploy, and run services on Kubernetes. The free tier supports connecting a local Kubernetes with mogenius, enabling individual developers to create a production-like test environment on their machine.

[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

## BaaS

  * [Activepieces](https://www.activepieces.com) - Build automation flows to connect several apps together in your app's backend. For example, send a Slack message or add a Google Sheet row when an event fires in your app. Free up to 5,000 tasks per month.
  * [back4app.com](https://www.back4app.com) - Back4App is an easy-to-use, flexible and scalable backend based on Parse Platform.
  * [backendless.com](https://backendless.com/) — Mobile and Web Baas, with 1 GB file storage free, push notifications of 50,000/month, and 1000 data objects in the table.
  * [BMC Developer Program](https://developers.bmc.com/site/global/bmc_helix_platform/program/overview/index.gsp) — The BMC Developer Program provides documentation and resources to build and deploy digital innovations for your enterprise. Access to a comprehensive, personal sandbox that includes the platform, SDK, and a library of components that can be used to build and tailor apps.
  * [convex.dev](https://convex.dev/) - Reactive backend as a service, hosting your data (documents with relationships & serializable ACID transactions), serverless functions, and WebSockets to stream updates to various clients. Free for small projects - up to 1M records, 5M monthly function calls.
  * [darklang.com](https://darklang.com/) - Hosted language combined with editor and infrastructure. Accessible during the beta, a generous free tier is planned after beta.
  * [Firebase](https://firebase.com) — Firebase helps you build and run successful apps. Free Spark Plan offers Authentication, Hosting, Firebase ML, Realtime Database, Cloud Storage, Testlab. A/B Testing, Analytics, App Distribution, App Indexing, Cloud Messaging (FCM), Crashlytics, Dynamic Links, In-App Messaging, Performance Monitoring, Predictions, and Remote Config are always free.
  * [Flutter Flow](https://flutterflow.io) — Build your Flutter App UI without writing a single line of code. Also has a Firebase integration. The free plan includes full access to UI Builder and Free templates.
  * [getstream.io](https://getstream.io/) — Build scalable In-App Chat, Messaging, Video and audio, and Feeds in a few hours instead of weeks
  * [hasura.io](https://hasura.io/) — Hasura extends your existing databases wherever it is hosted and provides an instant GraphQL API that can be securely accessed for web, mobile, and data integration workloads. Free for 1GB/month of data pass-through.
  * [iron.io](https://www.iron.io/) — Async task processing (like AWS Lambda) with free tier and 1-month free trial
  * [nhost.io](https://nhost.io) - Serverless backend for web and mobile apps. The free plan includes PostgreSQL, GraphQL (Hasura), Authentication, Storage, and Serverless Functions.
  * [nudge-hook.net](https://nudge-hook.net/client) — Job Scheduling API (with swagger/openapi client). Allows you to schedule as many ad-hoc/cron/periodic webhook deliveries as possible. Free for everyone (no signup required), but infinite schedules are limited to 500 'nudges' max. Accepts donations.
  * [onesignal.com](https://onesignal.com/) — Unlimited free push notifications
  * [paraio.com](https://paraio.com) — Backend service API with flexible authentication, full-text search and caching. Free for one app, 1GB of app data.
  * [progress.com](https://www.progress.com/kinvey) — Mobile backend, starter plan has unlimited requests/second, with 1 GB of data storage. Enterprise application support
  * [pubnub.com](https://www.pubnub.com/) — Free push notifications for up to 1 million messages/month and 100 active daily devices
  * [pushbots.com](https://pushbots.com/) — Push notification service. Free for up to 1.5 million pushes/month
  * [pushcrew.com](https://pushcrew.com/) — Push notification service. Unlimited notifications for up to 2,000 Subscribers
  * [pusher.com](https://pusher.com/beams) — Free, unlimited push notifications for 2000 monthly active users. A single API for iOS and Android devices.
   * [engagespot.co](https://engagespot.co/) — Notification infrastructure for developers. Free for up to 100 monthly active users.
  * [quickblox.com](https://quickblox.com/) — A communication backend for instant messaging, video, and voice calling, and push notifications
  * [restspace.io](https://restspace.io/) - Configure a server with services for auth, data, files, email API, templates, and more, then compose into pipelines and transform data.
  * [Salesforce Developer Program](https://developer.salesforce.com/signup) — Build apps Lightning fast with drag-and-drop tools. Customize your data model with clicks. Go further with Apex code. Integrate with anything using powerful APIs. Stay protected with enterprise-grade security. Customize UI with clicks or any leading-edge web framework. Free Developer Program gives access to the full Lightning Platform.
  * [ServiceNow Developer Program](https://developer.servicenow.com/) — Rapidly build, test, and deploy applications that make work better for your organization. Free Instance & access to early previews.
  * [simperium.com](https://simperium.com/) — Move data everywhere instantly and automatically, multi-platform, unlimited sending and storage of structured data, max. 2,500 users/month
  * [Singlebase.cloud](https://singlebase.cloud) — SinglebaseCloud is an AI-powered all-in-one backend platform to accelerate app development. It offers tools like Vector DB, Relational Document DB, Auth, Search, and Storage, aiming to simplify backend development. Free/Starter Plan offers Relational Document DB, Auth, Search, Storage. 
  * [stackstorm.com](https://stackstorm.com/) — Event-driven automation for apps, services, and workflows, free without flow, access control, LDAP
  * [streamdata.io](https://streamdata.io/) — Turns any REST API into an event-driven streaming API. Free plan up to 1 million messages and ten concurrent connections.
  * [Supabase](https://supabase.com) — The Open Source Firebase Alternative to build backends. Free Plan offers Authentication, Realtime Database & Object Storage.
  * [tyk.io](https://tyk.io/) — API management with authentication, quotas, monitoring and analytics. Free cloud offering
  * [zapier.com](https://zapier.com/) — Connect the apps you use to automate tasks. Five zaps every 15 minutes and 100 tasks/month
  * [IFTTT](https://ifttt.com) — Automate your favorite apps and devices. Free 2 Applets
  * [Integrately](https://integrately.com) — Automate tedious tasks with a single click. Free 100 Tasks, 15 Minute
Update Time, five active automations, webhooks.
  * [LeanCloud](https://leancloud.app/) — Mobile backend. 1GB of data storage, 256MB instance, 3K API requests/day, and 10K pushes/day are free. (API is very similar to Parse Platform)

[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

## Low-code Platform

  * [Basedash](https://www.basedash.com) — Low-code platform for building internal admin panels and dashboards. Supports SQL databases and REST APIs.
  * [BudiBase](https://budibase.com/) — Budibase is an open-source low-code platform for creating internal apps in minutes. Supports PostgreSQL, MySQL, MSSQL, MongoDB, Rest API, Docker, K8s
  * [appsmith](https://www.appsmith.com/) — Low code project to build admin panels, internal tools, and dashboards. Integrates with 15+ databases and any API.
  * [ToolJet](https://www.tooljet.com/) — Extensible low-code framework for building business applications. Connect to databases, cloud storages, GraphQL, API endpoints, Airtable, etc., and build apps using drag-and-drop application builder.
  * [ReTool](https://retool.com/) — Low-code platform for building internal applications. Retool is highly hackable. If you can write it with JavaScript and an API, you can make it in Retool. The free tier allows up to five users per month, unlimited apps and API connections.
  * [DronaHQ](https://www.dronahq.com/) — DronaHQ - a low code platform that helps engineering teams and product managers to build internal tools, custom user journeys, digital experiences, automation, custom admin panels, operational apps 10X faster.
  * [ILLA Cloud](https://www.illacloud.com/) — ILLA Cloud - A robust open-source low-code platform for developers to build internal tools. By using ILLA's library of Components and Actions, developers can save massive amounts of time on building tools. Free for 5 team members.
  * [outsystems.com](https://www.outsystems.com/) — Enterprise web development PaaS for on-premise or cloud, free "personal environment" offering allows for unlimited code and up to 1 GB database


[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

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
  * [Lecturify](https://www.lecturify.net/index.en.html) - Web hosting with SFPT access for file upload and download, php available.
  * [Neocities](https://neocities.org) — Static, 1 GB free storage with 200 GB Bandwidth.
  * [Netlify](https://www.netlify.com/) — Builds, deploys and hosts static site/app free for 100 GB data and 100 GB/month bandwidth.
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
  * [fleek.co](https://fleek.co/) - Build modern sites and apps on the Open Web and its protocols seamlessly free for unlimited websites and 50 GB/month bandwidth.
  * [MDB GO](https://mdbgo.com/) - Free hosting for one project with two weeks Container TTL, 500 MB RAM per project, SFTP - 1G disk space.
  * [Patr Cloud](https://patr.cloud/) — An easy-to-use cloud platform, among its paid services it offers to host three static sites for free.
  * [Serv00.com](https://serv00.com/) — 3 GB of free web hosting with daily backups (7 days). Support: Crontab jobs, SSH access, repositories (GIT, SVN, and Mercurial), support: MySQL, PostgreSQL, MongoDB, PHP, Node.js, Python, Ruby, Java, Perl, TCL/TK, Lua, Erlang, Rust, Pascal, C, C++, D, R, and many more.

[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

## DNS

  * [1.1.1.1](https://developers.cloudflare.com/1.1.1.1/) - Free public DNS Resolver, which is fast and secure (encrypt your DNS query), provided by Cloudflare. Useful to bypass your internet provider's DNS blocking, prevent DNS query spying, and [to block adult & malware content](https://developers.cloudflare.com/1.1.1.1/1.1.1.1-for-families). It can also be used [via API](https://developers.cloudflare.com/1.1.1.1/encrypted-dns/dns-over-https/make-api-requests). Note: Just a DNS resolver, not a DNS hoster.
  * [1984.is](https://www.1984.is/product/freedns/) — Free DNS service with API and lots of other free DNS features included.
  * [cloudns.net](https://www.cloudns.net/) — Free DNS hosting up to 1 domain with 50 records
  * [deSEC](https://desec.io) - Free DNS hosting with API support, designed with security in mind. Runs on open-source software and is supported by [SSE](https://www.securesystems.de/).
  * [dns.he.net](https://dns.he.net/) — Free DNS hosting service with Dynamic DNS Support
  * [Zonomi](https://zonomi.com/) — Free DNS hosting service with instant DNS propagation. Free plan: 1 DNS zone (domain name) with up to 10 DNS records.
  * [dnspod.com](https://www.dnspod.com/) — Free DNS hosting.
  * [duckdns.org](https://www.duckdns.org/) — Free DDNS with up to 5 domains on the free tier. With configuration guides for various setups.
  * [freedns.afraid.org](https://freedns.afraid.org/) — Free DNS hosting. Also, provide free subdomains based on numerous public user [contributed domains](https://freedns.afraid.org/domain/registry/). Get free subdomains from the "Subdomains" menu after signing up.
  * [luadns.com](https://www.luadns.com/) — Free DNS hosting, three domains, all features with reasonable limits
  * [namecheap.com](https://www.namecheap.com/domains/freedns/) — Free DNS. No limit on the number of domains
  * [nextdns.io](https://nextdns.io) - DNS-based firewall, 300K free queries monthly
  * [noip](https://www.noip.com/) — a dynamic DNS service that allows up to 3 hostnames free with confirmation every 30 days
  * [sslip.io](https://sslip.io/) — Free DNS service that when queried with a hostname with an embedded IP address returns that IP address.
  * [zilore.com](https://zilore.com/en/dns) — Free DNS hosting for 5 domains.
  * [zoneedit.com](https://www.zoneedit.com/free-dns/) — Free DNS hosting with Dynamic DNS Support.
  * [zonewatcher.com](https://zonewatcher.com) — Automatic backups and DNS change monitoring. One domain free
  * [huaweicloud.com](https://www.huaweicloud.com/intl/en-us/product/dns.html) – Free DNS hosting by Huawei
  * [Hetzner](https://www.hetzner.com/dns-console) – Free DNS hosting from Hetzner with API support.
  * [Glauca](https://docs.glauca.digital/hexdns/) – Free DNS hosting for up to 3 domains and DNSSEC support

[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

## Domain

  * [eu.org](https://nic.eu.org) — Free eu.org domain. The request is usually approved in 14 days.
  * [pp.ua](https://nic.ua/) — Free pp.ua subdomains.

[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

## IaaS

  * [4EVERLAND](https://www.4everland.org/) — Compatible with AWS S3 - APIs, interface operations, CLI, and other upload methods, upload and store files from the IPFS and Arweave networks in a safe, convenient, and efficient manner. Registered users can get 6 GB of IPFS storage and 300MB of Arweave storage for free. Any Arweave file uploads smaller than 150 KB are free.
  * [backblaze.com](https://www.backblaze.com/b2/) — Backblaze B2 cloud storage. Free 10 GB (Amazon S3-like) object storage for unlimited time
  * [filebase.com](https://filebase.com/) - S3 Compatible Object Storage Powered by Blockchain. 5 GB free storage for an unlimited duration.
  * [Storj](https://storj.io/) — Decentralised Private Cloud Storage for Apps and Developers. The free plan provides 1 Project, 25 GB storage, and 25 GB monthly bandwidth.
  * [Tebi](https://tebi.io/) - S3 compatibility object storage.Free 25 GB storage and 250GB outbound transfer.
  * [Idrive e2](https://www.idrive.com/e2/) - S3 compatibility object storage. 10 GB free storage and 10 GB download bandwidth per month.
  * [C2 Object Storage](https://c2.synology.com/en-us/pricing/object-storage) - S3 compatibility object storage. 15 GB free storage and 15 GB downloads per month.
  * [Spheron](https://spheron.network/) — From Decentralised Cloud Storage and web Hosting to Decentralised Compute for Apps and developers under one platform, the Free plan provides 5GB Storage, 100GB Bandwidth, Unlimited Domain and projects, $5 worth of Compute resources (Worth $50 w.r.t AWS).

[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

## Managed Data Services

   * [Aiven](https://aiven.io/) - Aiven offers free PostgreSQL, MySQL and Redis plans on its open-source data platform. Single node, 1 CPU, 1GB RAM, and for PostgreSQL and MySQL, 5GB storage. Easy migration to more extensive plans or across clouds.
   * [airtable.com](https://airtable.com/) — Looks like a spreadsheet, but it's a relational database unlimited bases, 1,200 rows/base, and 1,000 API requests/month
   * [Astra](https://www.datastax.com/products/datastax-astra/) — Cloud Native Cassandra as a Service with [80GB free tier](https://www.datastax.com/products/datastax-astra/pricing)
   * [codehooks.io](https://codehooks.io/) — JavaScript serverless API/backend and database service with functions, Mongdb-ish queries, key/value lookups, a job system, and a message queue. One instance free per project, 5000 records, 5000 calls/month free, three developers included. No credit-card required.
   * [CrateDB](https://crate.io/) - Distributed Open Source SQL database for real-time analytics. [Free Tier CRFREE](https://crate.io/lp-crfree): One-node with 2 CPUs, 2 GiB of memory, 8 GiB of storage. One cluster per organization, no payment method needed.
   * [FaunaDB](https://fauna.com/) — Serverless cloud database with native GraphQL, multi-model access, and daily free tiers up to 100 MB
   * [Upstash](https://upstash.com/) — Serverless Redis with free tier up to 10,000 requests per day, 256MB max database size, and 20 concurrent connections
   * [MongoDB Atlas](https://www.mongodb.com/cloud/atlas) — free tier gives 512 MB
   * [redsmin.com](https://www.redsmin.com/) — Online real-time monitoring and administration service for Redis, Monitoring for 1 Redis instance free
   * [redislabs](https://redislabs.com/try-free/) - Free 30MB redis instance
   * [MemCachier](https://www.memcachier.com/) — Managed Memcache service. Free for up to 25MB, 1 Proxy Server, and basic analytics
   * [scalingo.com](https://scalingo.com/) — Primarily a PaaS but offers a 128MB to 192MB free tier of MySQL, PostgreSQL, or MongoDB
   * [SeaTable](https://seatable.io/) — Flexible, Spreadsheet-like Database built by the Seafile team. unlimited tables, 2,000 lines, 1-month versioning, up to 25 team members.
   * [skyvia.com](https://skyvia.com/) — Cloud Data Platform offers a free tier and all plans are completely free while in beta
   * [StackBy](https://stackby.com/) — One tool that combines spreadsheets' flexibility, databases' power, and built-in integrations with your favorite business apps. The free plan includes unlimited users, ten stacks, and a 2GB attachment per stack.
   * [TiDB Cloud](https://en.pingcap.com/tidb-cloud/) — TiDB is an open-source MySQL-compatible distributed HTAP RDBMS. TiDB Serverless provides 5GB of row storage, 5GB of column storage, and 50 million Request Units (RUs) for free each month.
   * [Turso by ChiselStrike](https://chiselstrike.com/) - Turso is SQLite Developer Experience in an Edge Database. Turso provides a Free Forever starter plan, 8 GB of total storage, Up to 3 databases, Up to 3 locations, 1 billion row reads per month, and Local development support with SQLite.
   * [InfluxDB](https://www.influxdata.com/) — Timeseries database, free up to 3MB/5 minutes writes, 30MB/5 minutes reads and 10,000 cardinalities series
   * [restdb.io](https://restdb.io/) - a fast and straightforward NoSQL cloud database service. With restdb.io you get schema, relations, automatic REST API (with MongoDB-like queries), and an efficient multi-user admin UI for working with data. The free plan allows 3 users, 2500 records, and 1 API request per second.
   * [cockroachlabs.com](https://www.cockroachlabs.com/free-tier/) — Free CockroachDB up to 5GB and 1vCPU (limited [request units](https://www.cockroachlabs.com/docs/cockroachcloud/serverless-faqs.html#what-are-the-usage-limits-of-cockroachdb-serverless-beta))
   * [Neo4j Aura](https://neo4j.com/cloud/aura/) — Managed native Graph DBMS / analytics platform with a Cypher query language and a REST API. Limits on graph size (50k nodes, 175k relationships).
   * [Neon](https://neon.tech/) — Managed PostgreSQL, 0.5 GB of storage (total), 1 Project ,10 branches, Unlimited Databases, always-available primary branch ( Auto suspend after 5 minutes), 20 hours of Active time per month (total) for non-primary branch compute.
   * [Dgraph Cloud](https://cloud.dgraph.io/pricing?type=free) — Managed native Graph DBMS with a GraphQL API. Limited to 1 MB data transfer per day.
   * [Tinybird](https://tinybird.co) - A serverless managed ClickHouse with connection-less data ingest over HTTP and lets you publish SQL queries as managed HTTP APIs. There is no time limit on free-tier, 10GB storage + 1000 API requests per day.
   * [TigerGraph Cloud](https://www.tigergraph.com/cloud/) — Managed native Graph DBMS / analytics platform with a SQL-like graph query language and a REST API. One free instance with two vCPU, 8GB Memory, and 50GB storage that sleeps after 1 hour of inactivity.
   * [TerminusCMS](https://terminusdb.com/pricing) — Managed free service for TerminusDB, a document and graph database written in Prolog and Rust. Free for dev, paid service for enterprise deployments and support.
   * [Planetscale](https://planetscale.com/) - PlanetScale is a MySQL-compatible, serverless database platform powered by Vitess, one database for free with 1 Production branch and 1 Development branch, 5GB storage, 1 Billion rows read/mo per database, and 10 Million rows written/mo per database.
   * [YugabyteDB](https://cloud.yugabyte.com) - YugabyteDB is a distributed SQL database compatible with PostgreSQL. The cloud-free tier includes two vCPU, 4GB RAM, and 10GB Disk.
   * [filess.io](https://filess.io) - filess.io is a platform where you can create one database of the following DBMS for free: MySQL, MariaDB, MongoDB, and PostgreSQL.
   * [xata.io](https://xata.io) - Xata is a serverless database with built-in powerful search and analytics. One API, multiple type-safe client libraries, and optimized for your development workflow. The free-forever tier is sufficient for hobby developers which comes with three units of Xata, please refer to the website for unit definition.
   * [8base.com](https://www.8base.com/) - 8base is a full-stack low-code development platform built for JavaScript developers built on top of MySQL and GraphQL and serverless backend-as-a-service. It allows you to start building web applications quickly using a UI app builder and scale quickly, The Free tier includes rows: 2,500, Storage: 500, Serverless computing: 1Gb/h, and client app users: 5.



[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

## Tunneling, WebRTC, Web Socket Servers and Other Routers

   * [Pinggy](https://pinggy.io) — Public URLs for localhost with a single command, no downloads required. HTTPS / TCP / TLS tunnels. The free plan has 60 minutes tunnel lifetime.
   * [conveyor.cloud](https://conveyor.cloud/) — Visual Studio extension to expose IIS Express to the local network or over a tunnel to a public URL.
   * [Hamachi](https://www.vpn.net/) — LogMeIn Hamachi is a hosted VPN service that lets you securely extend LAN-like networks to distributed teams with a free plan that allows unlimited networks with up to 5 people
   * [Mirna Sockets](https://mirna.cloud/) - Free Socket as a Service Platform that gives you a wss:// URL when deploying your Web Socket Server code and also allows you to monitor its performance.
   * [localhost.run](https://localhost.run/) — Expose locally running servers over a tunnel to a public URL.
   * [localtunnel](https://theboroer.github.io/localtunnel-www/) — Expose locally running servers over a tunnel to a public URL. Free hosted version, and [open source](https://github.com/localtunnel/localtunnel).
   * [ngrok.com](https://ngrok.com/) — Expose locally running servers over a tunnel to a public URL.
   * [Radmin VPN](https://www.radmin-vpn.com/) — Connect multiple computers together via a VPN-enabling LAN-like network. Unlimited peers. (Hamachi alternative)
   * [segment.com](https://segment.com/) — Hub to translate and route events to other third-party services. 100,000 events/month free
   * [STUN](https://en.wikipedia.org/wiki/STUN) — Session Traversal of User Datagram Protocol [UDP] Through Network Address Translators [NATs])
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
   * [Metered](https://www.metered.ca/) — Free TURN server with 50GB included monthly TURN usage.

[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

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
   * [diagrams.net](https://app.diagrams.net/) — Online diagrams stored locally in Google Drive, OneDrive, or Dropbox. Free for all features and storage levels
   * [freedcamp.com](https://freedcamp.com/) - tasks, discussions, milestones, time tracking, calendar, files and password manager. Free plan with unlimited projects, users, and file storage.
   * [easyretro.io](https://www.easyretro.io/) — Simple and intuitive sprint retrospective tool. The free plan has three public boards and one survey per board per month.
   * [GForge](https://gforge.com) — Project Management and issue Tracking toolset for complex projects with self-premises and SaaS options. SaaS free plan offers the first five users free & free for Open Source Projects.
   * [gleek.io](https://www.gleek.io) — Free description-to-diagrams tool for developers. Create informal UML class, object, or entity-relationship diagrams using your keyword.
   * [GraphQL Inspector](https://github.com/marketplace/graphql-inspector) - GraphQL Inspector outputs a list of changes between two GraphQL schemas. Every difference is precisely explained and marked as breaking, non-breaking, or dangerous.
   * [huboard.com](https://huboard.com/) — Instant project management for your GitHub issues, free for Open Source
   * [Hygger](https://hygger.io) — Project management platform. The free plan offers unlimited users, projects & boards with 100 MB of Storage.
   * [Instabug](https://instabug.com) —  A comprehensive bug reporting and in-app feedback SDK for mobile apps. Free plan up to 1 app and one member.
   * [WishKit](https://wishkit.io) —  Collect in-app user feedback for your iOS/macOS app and prioritize features based on user votes. Free plan up to 1 app.
   * [Ilograph](https://www.ilograph.com/)  — interactive diagrams that allow users to see their infrastructure from multiple perspectives and levels of detail. Charts can be expressed in code. The free tier has unlimited private diagrams with up to 3 viewers.
   * [Jira](https://www.atlassian.com/software/jira) — Advanced software development project management tool used in many corporate environments. Free plan for up to 10 users.
   * [kanbanflow.com](https://kanbanflow.com/) — Board-based project management. Free, premium version with more options
   * [kanbantool.com](https://kanbantool.com/) — Kanban board-based project management. The free plan has two boards and two users, without attachments or files.
   * [Kitemaker.co](https://kitemaker.co) - Collaborate through all phases of the product development process and keep track of work across Slack, Discord, Figma, and Github. Unlimited users, unlimited spaces. Free plan up to 250 work items.
   * [Kiter.app](https://www.kiter.app/) - Let anyone organize their job search and track interviews, opportunities, and connections. Powerful web app and Chrome extension. Completely free.
   * [Kumu.io](https://kumu.io/)  — Relationship maps with animation, decorations, filters, clustering, spreadsheet imports, etc. The free tier allows unlimited public projects. Graph size unlimited. Free private projects for students. Sandbox mode is available if you prefer not to leave your file publicly online (upload, edit, download, discard).
   * [Linear](https://linear.app/) — Issue tracker with a streamlined interface. Free for unlimited members, up to 10MB file upload size, 250 issues (excluding Archive)
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
   * [SpeedBoard](https://speedboard.app) - Board for Agile and Scrum retrospectives - Free.
   * [SuperPM](https://superpm.app/) - Versatile project management platform. Free for up to 3 projects, unlimited users, 1 GB storage.
   * [Tadum](https://tadum.app) - Meeting agenda and minutes app designed for recurring meetings, free for teams of up to 10
   * [taiga.io](https://taiga.io/) — Project management platform for startups and agile developers, free for Open Source
   * [Tara AI](https://tara.ai/) — Simple sprint management service. The free plan has unlimited tasks, sprints, and workspaces without user limits.
   * [targetprocess.com](https://www.targetprocess.com/) — Visual project management, from Kanban and Scrum to almost any operational process. Free for unlimited users, up to 1,000 data entities {[more details](https://www.targetprocess.com/pricing/)}
   * [taskade.com](https://www.taskade.com/) — Real-time collaborative task lists and team outlines. The free plan has one workspace with unlimited tasks and projects; 1GB file storage; 1-week project history; and five attendees per video meeting.
   * [taskulu.com](https://taskulu.com/) — Role based project management. Free up to 5 users. Integration with GitHub/Trello/Dropbox/Google Drive
   * [teamwork.com](https://teamwork.com/) — Project management & Team Chat. Free for five users and two projects. Premium plans are available.
   * [teleretro.com](https://www.teleretro.com/) — Simple and fun retrospective tool with icebreakers, gifs and emojis. The free plan includes three retros and unlimited members.
   * [testlio.com](https://testlio.com/) — Issue tracking, test management and beta testing platform. Free for private use
   * [terrastruct.com](https://terrastruct.com/) — Online diagram maker specifically for software architecture. Free tier up to 4 layers per diagram.
   * [todoist.com](https://todoist.com/) — Collaborative and individual task management. The free plan has: 5 active projects, five users in the project, file uploading up to 5MB, three filters, and one week of activity history.
   * [trello.com](https://trello.com/) — Board-based project management. Unlimited Personal Boards, 10 Team Boards.
   * [Tweek](https://tweek.so/) — Simple Weekly To-Do Calendar & Task Management.
   * [ubertesters.com](https://ubertesters.com/) — Test platform, integration and crowd testers, 2 projects, five members
   * [vabotu](https://vabotu.com/) - A collaborative tool for project management. Free and other plans are available. The Freelance plan is for ten users and includes messaging, task boards, 5GB online storage, workspaces, and export data.
   * [Wikifactory](https://wikifactory.com/) — Product designing Service with Projects, VCS & Issues. The free plan offers unlimited projects & collaborators and 3GB storage.
   * [Yodiz](https://www.yodiz.com/) — Agile development and issue tracking. Free up to 3 users, unlimited projects.
   * [YouTrack](https://www.jetbrains.com/youtrack/buy/#edition=incloud) — Free hosted YouTrack (InCloud) for FOSS projects and private projects (free for three users). Includes time tracking and agile boards
   * [zenhub.com](https://www.zenhub.com) — The only project management solution inside GitHub. Free for public repos, OSS, and nonprofit organizations
   * [zenkit.com](https://zenkit.com) — Project management and collaboration tool. Free for up to 5 members, 5 GB attachments.
   * [Zube](https://zube.io) — Project management with free plan for 4 Projects & 4 users. GitHub integration is available.
   * [Toggl](https://toggl.com/) — Provides two free productivity tools. [Toggl Track](https://toggl.com/track/) for time management and tracking app with a free plan provides seamless time tracking and reporting designed with freelancers in mind. It has unlimited tracking records, projects, clients, tags, reporting, and more. And [Toggl Plan](https://toggl.com/plan/) for task planning with a free plan for solo developers with unlimited tasks, milestones, and timelines.
   * [Sflow](https://sflow.io) — sflow.io is a project management tool built for agile software development, marketing, sales, and customer support, especially for outsourcing and cross-organization collaboration projects. Free plan up to 3 projects and five members.
   * [Pulse.red](https://pulse.red) — Free Minimalistic Time Tracker and Timesheet app for projects.

[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

## Storage and Media Processing

   * [AndroidFileHost](https://androidfilehost.com/) - Free file-sharing platform with unlimited speed, bandwidth, file count, download count, etc. It is mainly aimed for Android dev-related files like APK build, custom ROM & modifications, etc. But seems to accept any other files as well.
   * [borgbase.com](https://www.borgbase.com/) — Simple and secure offsite backup hosting for Borg Backup. 10 GB free backup space and two repositories.
   * [icedrive.net](https://www.icedrive.net/) - Simple cloud storage service. 10 GB free storage
   * [sync.com](https://www.sync.com/) - End-to-End cloud storage service. 5 GB of free storage
   * [pcloud.com](https://www.pcloud.com/) - Cloud storage service. Up to 10 GB of free storage
   * [sirv.com](https://sirv.com/) — Smart Image CDN with on-the-fly image optimization and resizing. The free tier includes 500 MB of storage and 2 GB of bandwidth.
   * [cloudimage.io](https://www.cloudimage.io/en/home) — Full image optimization and CDN service with 1500+ Points of Presence around the world. A variety of image resizing, compression, and watermarking functions. Open source plugins for responsive images, 360 image making and image editing. Free monthly plan with 25GB of CDN traffic 25GB of cache storage and unlimited transformations.
   * [cloudinary.com](https://cloudinary.com/) — Image upload, powerful manipulations, storage, and delivery for sites and apps, with Ruby, Python, Java, PHP, Objective-C, and more libraries. The free tier includes 25 monthly credits. One credit equals 1,000 image transformations, 1 GB of storage, or 1 GB of CDN usage.
   * [embed.ly](https://embed.ly/) — Provides APIs for embedding media in a webpage, responsive image scaling, and extracting elements from a webpage. Free for up to 5,000 URLs/month at 15 requests/second
   * [filestack.com](https://www.filestack.com/) — File picker, transform, and deliver, free for 250 files, 500 transformations, and 3 GB bandwidth
   * [file.io](https://www.file.io) - 2 GB storage of files. A file is auto-deleted after one download. REST API to interact with the storage. Rate limit one request/minute.
   * [freetools.site](https://freetools.site/) — Free online tools. Convert or edit documents, images, audio, video, and more.
   * [GoFile.io](https://gofile.io/) - Free file sharing and storage platform can be used via web-based UI & also API. unlimited file size, bandwidth, download count, etc. But it will be deleted when a file becomes inactive (no download for more than ten days).
   * [gumlet.com](https://www.gumlet.com/) — Image and video hosting, processing and streaming via CDN. Provides generous free tier of 250 GB / month for videos and 30 GB  / month for images.
   * [image-charts.com](https://www.image-charts.com/) — Unlimited image chart generation with a watermark
   * [Imgbot](https://github.com/marketplace/imgbot) — Imgbot is a friendly robot that optimizes your images and saves you time. Optimized images mean smaller file sizes without sacrificing quality. It's free for open source.
   * [imgen](https://www.jitbit.com/imgen/) - Free unlimited social cover image generation API, no watermark
   * [kraken.io](https://kraken.io/) — Image optimization for website performance as a service, free plan up to 1 MB file size
   * [kvstore.io](https://www.kvstore.io/) — Key-value storage service. The free tier allows 100 keys, 1KB/key, 100 calls/hour
   * [npoint.io](https://www.npoint.io/) — JSON store with collaborative schema editing
   * [nitropack.io](https://nitropack.io/) - Accelerate your site's speed on autopilot with complete front-end optimization (caching, images and code optimization, CDN). Free for up to 5,000 pageviews/month
   * [otixo.com](https://www.otixo.com/) — Encrypt, share, copy, and move all your cloud storage files from one place. The basic plan provides unlimited file transfer with 250 MB max. file size and allows five encrypted files
   * [packagecloud.io](https://packagecloud.io/) — Hosted Package Repositories for YUM, APT, RubyGem and PyPI.  Limited free plans and open-source plans are available via request
   * [getpantry.cloud](https://getpantry.cloud/) — A simple JSON data storage API perfect for personal projects, hackathons, and mobile apps!
   * [piio.co](https://piio.co/) — Responsive image optimization and delivery for every website. Free plan for developers and personal websites. Includes free CDN, WebP, and Lazy Loading out of the box.
   * [Pinata IPFS](https://pinata.cloud) — Pinata is the simplest way to upload and manage files on IPFS. Our friendly user interface and IPFS API make Pinata the easiest IPFS pinning service for platforms, creators, and collectors. 1 GB storage free, along with access to API.
   * [placekitten.com](https://placekitten.com/) — A quick and simple service for getting pictures of kittens for use as placeholders
   * [plot.ly](https://plot.ly/) — Graph and share your data. The free tier includes unlimited public files and ten private files
   * [podio.com](https://podio.com/) — You can use Podio with a team of up to five people and try out the features of the Basic Plan, except user management
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


[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

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
  * [Branition](https://branition.com/colors) - Hand-curated color pallets best fitted for brands.
  * [css-gradient.com](https://www.css-gradient.com/) - Free tool to quickly generate custom cross-browser CSS gradients. In RGB and HEX format.
  * [easyvectors.com](https://easyvectors.com/) — EasyVectors.com is a free SVG vector art stock. Download the best vector graphics absolutely for free.
  * [figma.com](https://www.figma.com) — Online, collaborative design tool for teams; free tier includes unlimited files and viewers with a max of 2 editors and three projects.
  * [framer.com](https://www.framer.com/) - Framer helps you iterate and animate interface ideas for your next app, website, or product—starting with powerful layouts. For anyone validating Framer as a professional prototyping tool: unlimited viewers, up to 2 editors, and up to 3 projects.
  * [freeforcommercialuse.net](https://freeforcommercialuse.net/) — FFCU Worry-free model/property release stock photos
  * [Gradientos](https://www.gradientos.app) - Makes choosing a gradient fast and easy.
  * [Icon Horse](https://icon.horse) – Get the highest resolution favicon for any website from our simple API.
  * [Iconoir](https://iconoir.com) – An open-source icons library with thousands of icons, supporting React, React Native, Flutter, Vue, Figma, and Framer.
  * [Icons8](https://icons8.com) — Icons, illustrations, photos, music, and design tools. Free Plan offers Limited formats in lower resolution. Link to Icons8 when you use our assets.
  * [Invision App](https://www.invisionapp.com) - UI design and prototyping tool. Desktop and web apps are available. Free to use with one active prototype.
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
  * [Octopus.do](https://octopus.do) — Visual sitemap builder. Build your website structure in real time and rapidly share it to collaborate with your team or clients.
  * [Pencil](https://github.com/evolus/pencil) - Open source design tool using Electron.
  * [Penpot](https://penpot.app) - Web-based, open-source design and prototyping tool. Supports SVG. Completely free.
  * [pexels.com](https://www.pexels.com/) - Free stock photos for commercial use. Has a free API that allows you to search photos by keywords.
  * [photopea.com](https://www.photopea.com) — A Free, Advanced online design editor with Adobe Photoshop UI supporting PSD, XCF & Sketch formats (Adobe Photoshop, Gimp and Sketch App).
  * [pixlr.com](https://pixlr.com/) — Free online browser editor on the level of commercial ones.
  * [Plasmic](https://www.plasmic.app/) - A fast, easy-to-use, robust web design tool and page builder that integrates into your codebase. Build responsive pages or complex components; optionally extend with code; and publish to production sites and apps.
  * [Pravatar](https://pravatar.cc/) - Generate a random/placeholder fake avatar whose URL can be directly hot-linked in your web/app.
  * [Proto.io](https://www.proto.io) - Create fully interactive UI prototypes without coding. The free tier is available when the free trial ends. The free tier includes one user, one project, five prototypes, 100MB of online storage, and a preview of the proto.io app.
  * [resizeappicon.com](https://resizeappicon.com/) — A simple service to resize and manage your app icons.
  * [Rive](https://rive.app) — Create and ship beautiful animations to any platform. Free forever for Individuals. The service is an editor that also hosts all the graphics on their servers. They also provide runtimes for many platforms to run representations made using Rive.
  * [storyset.com](https://storyset.com/) — Create incredible free customized illustrations for your project using this tool.
  * [smartmockups.com](https://smartmockups.com/) — Create product mockups, 200 free mockups.
  * [tabler-icons.io](https://tabler-icons.io/) — Over 1500 free copy-and-paste SVG editable icons.
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
  * [react-favicon.com](https://react-favicon.com/) - Generate Favicons for your website using React and JSX using any font and icon library.
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

[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

## Design Inspiration

  * [awwwards.](https://www.awwwards.com/) - [Top websites] A showcase of all the best-designed websites (voted on by designers).
  * [Behance](https://www.behance.net/) - [Design showcase] A place where designers showcase their work. Filterable with categories for UI/UX projects.
  * [dribbble](https://dribbble.com/) - [Design showcase] Unique design inspiration, generally not from real applications.
  * [Landings](https://landings.dev/) - [Web Screenshots] Find the best landing pages for your design inspiration based on your preference.
  * [LovelyLanding.net](https://www.lovelylanding.net/) - [Landing Page Designs] Frequently updated landing page screenshots. Includes Desktop, Tablet, and Mobile screenshots.
  * [Mobbin](https://mobbin.design/) - [Mobile screenshots] Save hours of UI & UX research with our library of 50,000+ fully searchable mobile app screenshots.
  * [Mobile Patterns](https://www.mobile-patterns.com/) - [Mobile screenshots] A design inspirational library featuring the finest UI UX Patterns (iOS and Android) for designers, developers, and product makers to reference.
  * [Screenlane](https://screenlane.com/) - [Mobile screenshots] Get inspired and keep up with the latest web & mobile app UI design trends. Filterable by pattern and app.
  * [scrnshts](https://scrnshts.club/) - [Mobile screenshots] A hand-picked collection of the finest app store design screenshots.
  * [UI Garage](https://uigarage.net/) - [Mobile and web screenshots] Daily UI inspiration & patterns for designers and developers to find inspiration, tools, and the best resources for your project.
  * [Refero](https://refero.design/) - [Web screenshots] Tagged and searchable collection of design references from great web applications.
  * [Lapa Ninja](https://www.lapa.ninja/) - [Landing page / UI KIts / Web screenshots] Lapa Ninja is a gallery featuring the best 6025 landing page examples, free books for designers and free UI kits from around the web.


[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

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

[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

## Package Build System

   * [build.opensuse.org](https://build.opensuse.org/) — Package build service for multiple distros (SUSE, EL, Fedora, Debian, etc.).
   * [copr.fedorainfracloud.org](https://copr.fedorainfracloud.org) — Mock-based RPM build service for Fedora and EL.
   * [help.launchpad.net](https://help.launchpad.net/Packaging) — Ubuntu and Debian build service.

[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

## IDE and Code Editing

   * [3v4l](https://3v4l.org/) - Free online PHP shell and snippet-sharing site, that runs your code in 300+ PHP versions
   * [Android Studio](https://d.android.com/studio) — Android Studio provides the fastest tools for building apps on every type of Android device. Open Source IDE is free for everyone and the best Android app development. Available for Windows, Mac, Linux, and even ChromeOS!
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
   * [GitPod](https://www.gitpod.io) — Instant, ready-to-code dev environments for GitHub projects. The free tier includes 50 hours/month.
   * [ide.goorm.io](https://ide.goorm.io) goormIDE is full IDE on cloud. multi-language support, Linux-based container via the fully-featured web-based terminal, port forwarding, custom URL, real-time collaboration and chat, share link, Git/Subversion support. There are many more features (The free tier includes 1GB RAM and 10GB Storage per container, 5 Container slots).
   * [JDoodle](https://www.jdoodle.com) — Online compiler and editor for more than 60 programming languages with a free plan for REST API code compiling up to 200 credits per day.
   * [jetbrains.com](https://jetbrains.com/products.html) — Productivity tools, IDEs and deploy tools (aka [IntelliJ IDEA](https://www.jetbrains.com/idea/), [PyCharm](https://www.jetbrains.com/pycharm/), etc). Free license for students, teachers, Open Source and user groups.
   * [jsbin.com](https://jsbin.com) — JS Bin is another playground and code-sharing site of front-end web (HTML, CSS, and JavaScript. It Also supports Markdown, Jade, and Sass).
   * [jsfiddle.net](https://jsfiddle.net/) — JS Fiddle is a playground and code-sharing site of front-end web, supporting collaboration.
   * [JSONPlaceholder](https://jsonplaceholder.typicode.com/) Some REST API endpoints that return some fake data in JSON format. The source code is also available if you would like to run the server locally.
   * [Lazarus](https://www.lazarus-ide.org/) — Lazarus is a Delphi-compatible cross-platform IDE for Rapid Application Development.
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
      * [Desktop](https://code.visualstudio.com) - (Windows, macOS and Linux).
      * [Online](https://vscode.dev) - (Browser)
   * [Visual Studio Community](https://visualstudio.microsoft.com/vs/community/) — Fully-featured IDE with thousands of extensions, cross-platform app development (Microsoft extensions available for download for iOS and Android), desktop, web and cloud development, multi-language support (C#, C++, JavaScript, Python, PHP and more).
   * [VSCodium](https://vscodium.com/) - Community-driven, without telemetry/tracking, and freely-licensed binary distribution of Microsoft’s editor VSCode
   * [wakatime.com](https://wakatime.com/) — Quantified self-metrics about your coding activity using text editor plugins, limited plan for free.
   * [Wave Terminal](https://waveterm.dev/) - Wave is an open-source, cross-platform terminal for seamless workflows. Render anything inline. Save sessions and history. Powered by open web standards. MacOS and Linux.
   * [WebComponents.dev](https://webcomponents.dev/) — In-browser IDE to code web components in isolation with 58 templates available, supporting stories, and tests.
   * [PHPSandbox](https://phpsandbox.io/) — Online development environment for PHP
   * [WebDB](https://webdb.app) - Free Efficient Database IDE. Featuring Server Discovery, ERD, Data Generator, AI, NoSQL Structure Manager, Database Versioning and many more.


[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

## Analytics, Events and Statistics

   * [Dwh.dev](https://dwh.dev) - Data Cloud Observability Solution (Snowflake). Free for personal use.
   * [Hightouch](https://hightouch.com/) - Hightouch is a Reverse ETL platform that helps you sync customer data from your data warehouse to your CRM, marketing, and support tools. The free tier offers you one destination to sync data to.
   * [Avo](https://avo.app/) — Simplified analytics release workflow. Single-source-of-truth tracking plan, type-safe analytics tracking library, in-app debuggers, and data observability to catch all data issues before you release. Free for two workspace members and 1 hour data observability lookback.
   * [Branch](https://branch.io) — Mobile Analytics Platform. Free Tier offers up to 10K Mobile App Users with deep-linking & other services.
   * [Cauldron](https://cauldron.io) — Analytics open source solution that allows users to aggregate information from multiple collaboration platforms as different types of data sources (Git, Github, and Gitlab). The free tier includes an unlimited number of reports.
   * [Census](https://www.getcensus.com/) — Reverse ETL & Operational Analytics Platform. Sync 10 fields from your data warehouse to 60+ SaaS like Salesforce, Zendesk, or Amplitude.
   * [Clicky](https://clicky.com) — Website Analytics Platform. Free Plan for one website with 3000 views analytics.
   * [Databox](https://databox.com) — Business Insights & Analytics by combining other analytics & BI platforms. Free Plan offers 3 users, dashboards & data sources. 11M historical data records.
   * [Hitsteps.com](https://hitsteps.com/) — 2,000 pageviews per month for 1 website
   * [amplitude.com](https://amplitude.com/) — 1 million monthly events, up to 2 apps
   * [GoatCounter](https://www.goatcounter.com/) — GoatCounter is an open-source web analytics platform available as a hosted service (free for non-commercial use) or self-hosted app. It aims to offer easy-to-use and meaningful privacy-friendly web analytics as an alternative to Google Analytics or Matomo. The free tier is for non-commercial use and includes unlimited sites, six months of data retention, and 100k pageviews/month.
   * [Google Analytics](https://analytics.google.com/) — Google Analytics
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
   * [quantcast.com](https://www.quantcast.com/products/measure-audience-insights/) — Unlimited free analytics
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

[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

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
   * [usersurge.com](https://www.usersurge.com/) — 250K sessions per month for individuals.
   * [howuku.com](https://howuku.com) — Track user interaction, engagement, and event. Free for up to 5,000 visits/month
   * [UXtweak.com](https://www.uxtweak.com/) — Record and watch how visitors use your website or app. Free unlimited time for small projects

[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

## International Mobile Number Verification API and SDK

  * [numverify](https://numverify.com/) — Global phone number validation and lookup JSON API. 100 API requests/month
  * [veriphone](https://veriphone.io/) — Global phone number verification in a free, fast, reliable JSON API. 1000 requests/month

[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

## Payment and Billing Integration

  * [Glassfy](https://glassfy.io/) – In-app subscriptions infrastructure, real-time subscription events and out-of-the-box monetization tools on iOS, Android, Stripe and Paddle. Free up to $10k monthly revenue.
  * [Adapty.io](https://adapty.io/) – One-stop solution with open-source SDK for mobile in-app subscription integration to iOS, Android, React Native, Flutter, Unity, or web app. Free up to $10k monthly revenue.
  * [CoinMarketCap](https://coinmarketcap.com/api/) — Provides cryptocurrency market data including the latest crypto and fiat currency exchange rates. The free tier offers 10K call credits/month.
  * [CurrencyFreaks](https://currencyfreaks.com/) — Provides current and historical currency exchange rates. Free DEVELOPER plan available with 1000 requests/month.
  * [CoinGecko](https://www.coingecko.com/en/api) — Provides cryptocurrency market data including the latest crypto exchange rates and historical data. The demo api comes with a stable rate limit of 30 calls/min and a monthly cap of 10,000 calls.
  * [CurrencyApi](https://currencyapi.net/) — Live Currency Rates for Physical and Cryptocurrencies, delivered in JSON and XML. The free tier offers 1,250 API requests/month.
  * [currencylayer](https://currencylayer.com/) — Reliable Exchange Rates and Currency Conversion for your Business, 100 API requests/month free.
  * [exchangerate-api.com](https://www.exchangerate-api.com) - An easy-to-use currency conversion JSON API. The free tier updates once per day with a limit of 1,500 requests/month.
  * [FraudLabsPRO](https://www.fraudlabspro.com) — Help merchants to prevent payment fraud and chargebacks. Free Micro Plan available with 500 queries/month.
  * [FxRatesAPI](https://fxratesapi.com) — Provides real-time and historical exchange rates. The free tier requires attribution.
  * [MailPopin](https://mailpop.in) - Get the most of your Stripe notifications with contextualized information.
  * [Moesif API Monetization](https://www.moesif.com/) - Generate revenue from APIs via usage-based billing. Connect to Stripe, Chargebee, etc. The free tier offers 30,000 events/month.
  * [Nami ML](https://www.namiml.com/) - Complete platform for in-app purchases and subscriptions on iOS and Android, including no-code paywalls, CRM, and analytics.  Free for all base features to run an IAP business.
  * [RevenueCat](https://www.revenuecat.com/) — Hosted backend for in-app purchases and subscriptions (iOS and Android). Free up to $2.5k/mo in tracked revenue.
  * [vatlayer](https://vatlayer.com/) — Instant VAT number validation and EU VAT rates API, free 100 API requests/month
  * [Currencyapi](https://currencyapi.com) — Free currency conversion and exchange rate data API. Free 300 requests per month, 10 requests per minute for private use.

[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

## Docker Related

  * [canister.io](https://canister.io/) — 20 free private repositories for developers, 30 free private repositories for teams to build and store Docker images
  * [Container Registry Service](https://container-registry.com/) - Harbor based Container Management Solution. The free tier offers 1 GB of storage for private repositories.
  * [Docker Hub](https://hub.docker.com) — One free private repository and unlimited public repositories to build and store Docker images
  * [Play with Docker](https://labs.play-with-docker.com/) — A simple, interactive, fun playground to learn Docker.
  * [quay.io](https://quay.io/) — Build and store container images with unlimited free public repositories
  * [Platform9](https://platform9.com/) - Managed Kubernetes plane. The free plan offers management capabilities for up to 3 clusters & 20 nodes. Just so you know, you must provide cluster infrastructure by yourself.

[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

## Vagrant Related

  * [Vagrant Cloud](https://app.vagrantup.com) - HashiCorp Vagrant Cloud. Vagrant box hosting.
  * [Vagrantbox.es](https://www.vagrantbox.es/) — An alternative public box index

[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

## Dev Blogging Sites

  * [BearBlog](https://bearblog.dev/) - Minimalist, Markdown-powered blog and website builder.
  * [Dev.to](https://dev.to/) - Where programmers share ideas and help each other grow.
  * [Hashnode](https://hashnode.com/) — Hassle-free Blogging Software for Developers!.
  * [Medium](https://medium.com/) — Get more thoughtful about what matters to you.
  * [AyeDot](https://ayedot.com/) — Share your ideas, knowledge, and stories with the world for Free in the form of Modern multimedia short-format Miniblogs.

[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

## Commenting Platforms
  * [GraphComment](https://graphcomment.com/) - GraphComment is a comments platform that helps you build an active community from the website’s audience.
  * [Utterances](https://utteranc.es/) - A lightweight comments widget built on GitHub issues. Use GitHub issues for blog comments, wiki pages, and more!
  * [Disqus](https://disqus.com/) - Disqus is a networked community platform used by hundreds of thousands of sites all over the web.
  * [Remarkbox](https://www.remarkbox.com/) - Open source hosted comments platform, pay what you can for "One moderator on a few domains with complete control over behavior & appearance"
  * [IntenseDebate](https://intensedebate.com/) - A feature-rich comment system for WordPress, Tumblr, Blogger, and many other website platforms.

[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

## Screenshot APIs

  * [ApiFlash](https://apiflash.com) — A screenshot API based on Aws Lambda and Chrome. Handles full page, captures timing, and viewport dimensions.
  * [microlink.io](https://microlink.io/) – It turns any website into data such as metatags normalization, beauty link previews, scraping capabilities, or screenshots as a service. 250 requests/day every day free.
  * [ScreenshotAPI.net](https://screenshotapi.net/) - Screenshot API uses a straightforward API call to generate screenshots of any website. Built to scale and hosted on Google Cloud. Offers 100 free screenshots per month.
  * [screenshotlayer.com](https://screenshotlayer.com/) — Capture highly customizable snapshots of any website. Free 100 snapshots/month
  * [screenshotmachine.com](https://www.screenshotmachine.com/) — Capture 100 snapshots/month, png, gif and jpg, including full-length captures, not only home page
  * [PhantomJsCloud](https://PhantomJsCloud.com) — Browser automation and page rendering.  Free Tier offers up to 500 pages/day.  Free Tier since 2017.
  * [Webshrinker.com](https://webshrinker.com) — Web Shrinker provides website screenshots and domain intelligence API services. Free 100 requests/month.
  * [Httpic.com](https://httpic.com) — Turn any website into jpg, png or pdf. Capture full-page screenshots, adjust the viewport, and inject custom code. Free tier at 150 images/month.
  * [Screenshots](https://screenshotson.click) — Your API for Screenshots. With highly customizable options for capture. Free 100 screenshots/month.

[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

## Flutter Related and Building IOS Apps without Mac

  * [FlutLab](https://flutlab.io/) - FlutLab is a modern Flutter online IDE and the best place to create, debug, and build cross-platform projects. Build iOS (Without a Mac) and Android apps with Flutter.
  * [CodeMagic](https://codemagic.io/) - Codemagic is a fully hosted and managed CI/CD for mobile apps. You can build, test, and deploy with a GUI-based CI/CD tool. The free tier offers 500 free minutes/month and a Mac Mini instance with 2.3 GHz and 8 GB of RAM.
  * [FlutterFlow](https://flutterflow.io/) -  FlutterFlow is a browser-based drag-and-drop interface to build mobile app using flutter.

[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

## Browser-based hardware emulation written in Javascript

  * [JsLinux](https://bellard.org/jslinux) — a really fast x86 virtual machine capable of running Linux and Windows 2k.
  * [Jor1k](https://s-macke.github.io/jor1k/demos/main.html) —  an OpenRISC virtual machine capable of running Linux with network support.
  * [v86](https://copy.sh/v86) — an x86 virtual machine capable of running Linux and other OS directly into the browser.

[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

## Privacy Management
  * [Bearer](https://www.bearer.sh/) - Helps implement privacy by design via audits and continuous workflows so that organizations comply with GDPR and other regulations. The free tier is limited to smaller teams and the SaaS version only.
  * [Osano](https://www.osano.com/) - Consent management and compliance platform with everything from GDPR representation to cookie banners. The free tier offers basic features.
  * [Iubenda](https://www.iubenda.com/) - Privacy and cookie policies and consent management. The free tier offers limited privacy and cookie policy as well as cookie banners.
  * [Cookiefirst](https://cookiefirst.com/) - Cookie banners, auditing, and multi-language consent management solution. The free tier offers a one-time scan and a single banner.
  * [Ketch](https://www.ketch.com/) - Consent management and privacy framework tool. The free tier offers most features with a limited visitor count.
  * [Concord](https://www.concord.tech/) - Full data privacy platform, including consent management, privacy request handling (DSARs), and data mapping. Free tier includes core consent management features and they also provide a more advanced plan for free to verified open source projects.

[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

## Miscellaneous

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
  * [Form2Channel](https://form2channel.com) — Place a static html form on your website and receive submissions directly to Google Sheets, Email, Slack, Telegram, or HTTP. No coding is necessary.
  * [Format Express](https://www.format-express.dev) - Instant online format for JSON / XML / SQL.
  * [FOSSA](https://fossa.com/) - Scalable, end-to-end management for third-party code, license compliance and vulnerabilities.
  * [fullcontact.com](https://www.fullcontact.com/developer/pricing/) — Help your users know more about their contacts by adding social profile to your app. 500 free Person API matches/month
  * [Hook Relay](https://www.hookrelay.dev/) - Add webhook support to your app without the hassles: done-for-you queueing, retries with backoff, and logging. The free plan has 100 deliveries per day, 14-day retention, and 3 hook endpoints.
  * [http2.pro](https://http2.pro) — HTTP/2 protocol readiness test and client HTTP/2 support detection API.
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
  * [redirect.ing](https://redirect.ing/) - Fast & secure domain forwarding without managing servers or SSL certificates. Free plan includes 10 hostnames and 100,000 requests per month.
  * [redirect.pizza](https://redirect.pizza/) - Easily manage redirects with HTTPS support. The free plan includes 10 sources and 100,000 hits per month.
  * [ReqBin](https://www.reqbin.com/) — Post HTTP Requests Online. Popular Request Methods include GET, POST, PUT, DELETE, and HEAD. Supports Headers and Token Authentication. Includes a basic login system for saving your requests.
  * [Smartcar API](https://smartcar.com) - An API for cars to locate, get fuel tank, battery levels, odometer, unlock/lock doors, etc.
  * [snappify](https://snappify.com) - Enables developers to create stunning visuals. From beautiful code snippets to fully fletched technical presentations. The free plan includes up to 3 snaps at once with unlimited downloads and 5 AI-powered code explanations per month.
  * [Sunrise and Sunset](https://sunrisesunset.io/api/) - Get sunrise and sunset times for a given longitude and latitude.
  * [superfeedr.com](https://superfeedr.com/) — Real-time PubSubHubbub compliant feeds, export, analytics. Free with less customization
  * [SurveyMonkey.com](https://www.surveymonkey.com) — Create online surveys. Analyze the results online. The free plan allows only 10 questions and 100 responses per survey.
  * [Tiledesk](https://tiledesk.com) - Create chatbots and conversational apps. Bring them omnichannel: from your website (live chat widget) to WhatsApp. Free plan with unlimited chatbots.
  * [Versionfeeds](https://versionfeeds.com) — Custom RSS feeds for releases of your favorite software. Have the latest versions of your programming languages, libraries, or loved tools in one feed. (The first 3 feeds are free)
  * [videoinu](https://videoinu.com) — Create and edit screen recordings and other videos online.

[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

## Remote Desktop Tools

  * [Getscreen.me](https://getscreen.me) —  Free for 2 devices, no limits on the number and duration of sessions
  * [Apache Guacamole™](https://guacamole.apache.org/) — Open source clientless remote desktop gateway
  * [RemSupp](https://remsupp.com) — On-demand support and permanent access to devices (2 sessions/day for free)
  * [RustDesk](https://rustdesk.com/) - Open source virtual/remote desktop infrastructure for everyone!

[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

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

[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)

## Other Free Resources

  * [Buff.tools](https://buff.tools/) - An all-in-one digital toolbox featuring Web, SEO, AI, Domain Management, unit conversion, calculators, and Image Manipulation Tools.
  * [ElevateAI](https://www.elevateai.com) - Get up to 200 hours of audio transcription for free every month.
  * [get.localhost.direct](https://get.localhost.direct) — A better `*.localhost.direct` Wildcard public CA signed SSL cert for localhost development with sub-domain support
  * [Framacloud](https://degooglisons-internet.org/en/) — A list of Free/Libre Open Source Software and SaaS by the French non-profit [Framasoft](https://framasoft.org/en/).
  * [github.com — FOSS for Dev](https://github.com/tvvocold/FOSS-for-Dev) — A hub of free and Open Source software for developers.
  * [GitHub Education](https://education.github.com/pack) — Collection of free services for students. Registration required.
  * [Markdown Tools](https://markdowntools.com) - Tools for converting HTML, CSVs, PDFs, JSON, and Excel files to and from Markdown
  * [Microsoft 365 Developer Program](https://developer.microsoft.com/microsoft-365/dev-program) — Get a free sandbox, tools, and other resources you need to build solutions for the Microsoft 365 platform. The subscription is a 90-day [Microsoft 365 E5 Subscription](https://www.microsoft.com/microsoft-365/enterprise/e5) (Windows excluded) which is renewable. It is renewed if you're active in development(measured using telemetry data & algorithms).
  * [RedHat for Developers](https://developers.redhat.com) — Free access to Red Hat products including RHEL, OpenShift, CodeReady, etc. exclusively for developers. Individual plan only. Free e-books are also offered for reference.
  * [smsreceivefree.com](https://smsreceivefree.com/) — Provides free temporary and disposable phone numbers.
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
  * [Free Code Tools](https://freecodetools.org/) — Effective code tools which are 100% free. Markdown editor, Code minifier/beautifier, QR code generator, Open Graph Generator, Twitter card Generator, and more.
  * [regex101](https://regex101.com/) — Free this website allows you to test and debug regular expressions (regex). It provides a regex editor and tester, as well as helpful documentation and resources for learning regex.
  * [Kody Tools](https://www.kodytools.com/dev-tools) — 100+ dev tools including formatter, minifier, and converter.
  * [AdminMart](https://adminmart.com/) — High-Quality Free and Premium Admin Dashboard and Website Templates created with Angular, Bootstrap, React, VueJs, NextJS, and NuxtJS!
  * [Glob tester](https://globster.xyz/) — A website that allows you to design and test glob patterns. It also provides resources to learn glob patterns.
  * [OpenUtils](https://openutils.org/) - There are various free tools available for developers, such as HTML/CSS/JavaScript formatters, minifiers, converters, encoders/decoder,s and many others.
  * [SimpleRestore](https://simplerestore.io) - Hassle-free MySQL backup restoration. Restore MySQL backups to any remote database without code or a server.
  * [360Converter](https://www.360converter.com/) - Free tier useful website to convert: Video to Text && Audio to Text && Speech to Text && Real-time Audio to Text && YouTube Video to Text && add Video Subtitle. Maybe it will be helpful in a short video conversion or in a short youtube tutorial:)
  * [QRCodeBest](https://qrcode.best/) - Create custom QR codes with 13 templates, full privacy, and personal branding. Features tracking pixels, project categorization, and unlimited team seats on QRCode.Best.

[![Back to Top](assets/Back-To-Top.svg)](#table-of-contents)
