# [free-for.dev](https://free-for.dev)

Developers and Open Source authors now have a massive amount of services offering free tiers, but it can be hard to find them all to make informed decisions.

This is a list of software (SaaS, PaaS, IaaS, etc.) and other offerings that have free tiers for developers.

The scope of this particular list is limited to things that infrastructure developers (System Administrator, DevOps Practitioners, etc.) are likely to find useful. We love all the free services out there, but it would be good to keep it on topic. It's a bit of a grey line at times so this is a bit opinionated; do not be offended if I do not accept your contribution.

This list is the result of Pull Requests, reviews, ideas and work done by 500+ people. You too can help by sending [Pull Requests](https://github.com/ripienaar/free-for-dev) to add more services or by remove ones whose offerings have changed or been retired.

*NOTE:* This list is only for as-a-Service offerings, not for self-hosted software. For a service to be eligible it has to offer a free tier and not just a free trial. If the free tier is time-bucketed it has to be for at least a year. We also consider the free tier from a security perspective, so SSO is fine but I will not accept services that restrict TLS to paid-only tiers.

Table of Contents
=================

   * [Major Cloud Providers' Always-Free Limits](#major-cloud-providers)
   * [Analytics, Events and Statistics](#analytics-events-and-statistics)
   * [APIs, Data and ML](#apis-data-and-ml)
   * [Artifact Repos](#artifact-repos)
   * [BaaS](#baas)
   * [CDN and Protection](#cdn-and-protection)
   * [CI and CD](#ci-and-cd)
   * [CMS](#cms)
   * [Code Quality](#code-quality)
   * [Code Search and Browsing](#code-search-and-browsing)
   * [Crash and Exception Handling](#crash-and-exception-handling)
   * [Data Visualization on Maps](#data-visualization-on-maps)
   * [DBaaS](#dbaas)
   * [Design and UI](#design-and-ui)
   * [Dev Blogging Sites](#dev-blogging-sites)
   * [DNS](#dns)
   * [Docker Related](#docker-related)
   * [Email](#email)
   * [Font](#font)
   * [Forms](#forms)
   * [IaaS](#iaas)
   * [IDE and Code Editing](#ide-and-code-editing)
   * [International Mobile Number Verification API and SDK](#international-mobile-number-verification-api-and-sdk)
   * [Issue Tracking and Project Management](#issue-tracking-and-project-management)
   * [Log Management](#log-management)
   * [Management Systems](#management-system)
   * [Messaging and Streaming](#messaging)
   * [Miscellaneous](#miscellaneous)
   * [Monitoring](#monitoring)
   * [Other Free Resources](#other-free-resources)
   * [PaaS](#paas)
   * [Package Build System](#package-build-system)
   * [Payment and Billing Integration](#payment-and-billing-integration)
   * [Screenshot APIs](#screenshot-apis)
   * [Search](#search)
   * [Security and PKI](#security-and-pki)
   * [Source Code Repos](#source-code-repos)
   * [Storage and Media Processing](#storage-and-media-processing)
   * [STUN, WebRTC, Web Socket Servers and Other Routers](#stun-webrtc-web-socket-servers-and-other-routers)
   * [Testing](#testing)
   * [Tools for Teams and Collaboration](#tools-for-teams-and-collaboration)
   * [Translation Management](#translation-management)
   * [Vagrant Related](#vagrant-related)
   * [Visitor Session Recording](#visitor-session-recording)
   * [Web Hosting](#web-hosting)
   * [Commenting Platforms](#commenting-platforms)
   * [Browser based hardware emulation](#browser-based-hardware-emulation-written-in-javascript)

## Major Cloud Providers

  * [Google Cloud Platform](https://cloud.google.com)
    * App Engine - 28 frontend instance hours per day, 9 backend instance hours per day
    * Cloud Firestore - 1GB storage, 50,000 reads, 20,000 writes, 20,000 deletes per day
    * Compute Engine - 1 non-preemptible f1-micro, 30GB HDD, 5GB snapshot storage (restricted to certain regions)
    * Cloud Storage - 5GB, 1GB network egress
    * Cloud Shell - Web-based Linux shell/basic IDE with 5GB of persistent storage. 60 hours limit per week
    * Cloud Pub/Sub - 10GB of messages per month
    * Cloud Functions - 2 million invocations per month (includes both background and HTTP invocations)
    * Cloud Run - 2 million requests per month, 360,000 GB-seconds memory, 180,000 vCPU-seconds of compute time, 1 GB network egress from North America per month
    * Google Kubernetes Engine - No cluster management fee for one zonal cluster. Each user node is charged at standard Compute Engine pricing
    * BigQuery - 1 TB of querying per month, 10 GB of storage each month
    * Cloud Build - 120 build-minutes per day
    * Cloud Source Repositories - Up to 5 Users, 50 GB Storage, 50 GB Egress
    * Full, detailed list - https://cloud.google.com/free

  * [Amazon Web Services](https://aws.amazon.com)
    * Amazon DynamoDB - 25GB NoSQL DB
    * Amazon Lambda - 1 Million requests per month
    * Amazon SNS - 1 million publishes per month
    * Amazon Cloudwatch - 10 custom metrics and 10 alarms
    * Amazon Glacier - 10GB long-term object storage
    * Amazon SQS - 1 million messaging queue requests
    * Amazon CodeBuild - 100min of build time per month
    * Amazon Code Commit - 5 active users per month
    * Amazon Code Pipeline - 1 active pipeline per month
    * Full, detailed list - https://aws.amazon.com/free/?awsf.Free%20Tier%20Types=categories%23alwaysfree

  * [Microsoft Azure](https://azure.microsoft.com)
    * App service - 10 web, mobile or API apps
    * Functions - 1 million requests per month
    * DevTest Labs - Enable fast, easy, and lean dev-test environments
    * Active Directory - 500,000 objects
    * Active Directory B2C - 50,000 monthly stored users
    * Azure DevOps - 5 active users
    * Microsoft IoT Hub - 8,000 messages per day
    * Load Balancer - 1 free public load balanced IP (VIP)
    * Notification Hubs - 1 million push notifications
    * Bandwidth - 5GB egress per month
    * Azure Cosmos DB - 5GB storage and 400 RUs of provisioned throughput for 1 year
    * [Azure Static Web Apps](https://azure.microsoft.com/pricing/details/app-service/static/?WT.mc_id=free-for-dev-github-wachegha) — Build, deploy and host static apps and serverless functions, with free SSL, Authenticationa/Authorisations and custom domains
    * Full, detailed list - https://azure.microsoft.com/en-us/free/

  * [Oracle Cloud](https://www.oracle.com/cloud/)
    * Compute - 2 VM.Standard.E2.1.Micro 1GB RAM
    * Block Volume - 2 volumes, 100 GB total (used for compute)
    * Object Storage - 10 GB
    * Load balancer - 1 instance with 10 Mbps
    * Databases - 2 DBs, 20 GB each
    * Monitoring - 500 million ingestion datapoints, 1 billion retrieval datapoints
    * Bandwidth - 10TB egress per month
    * Notifications - 1 million delivery options per month, 1000 emails sent per month
    * Full, detailed list - https://www.oracle.com/cloud/free/

  * [IBM Cloud](https://www.ibm.com/cloud/free/)
    * Cloud Functions - 5 million executions per month
    * Object Storage - 25GB per month
    * Cloudant database - 1 GB of data storage
    * Db2 database - 100MB of data storage
    * API Connect - 50,000 API calls per month
    * Availability Monitoring - 3 million data points per month
    * Log Analysis - 500MB of daily log
    * Full, detailed list - https://www.ibm.com/cloud/free/

  * [Alibaba Cloud](https://www.alibabacloud.com/campaign/free-trial)
    * Compute - 1 ecs.t5-lc1m1.small for 12 months with 40 GB ultra cloud disk or SSD disk and 1 MB internet bandwidth.
    * Function Compute - 1 million calls free each month, 400,000 GB-seconds free each month
    * API Gateway - For the 1st year you activate API Gateway, you get 1 million free calls each month.
    * .tech Domain Name - Free to use for one year
    * Full, detailed list - https://www.alibabacloud.com/campaign/free-trial

## Source Code Repos

  * [Azure DevOps](https://azure.microsoft.com/services/devops/) — Unlimited private repos (Git and TFS) for up to 5 users/team
  * [bitbucket.org](https://bitbucket.org/) — Unlimited public and private Git repos for up to 5 users with Pipelines for CI/CD
  * [chiselapp.com](http://chiselapp.com/) — Unlimited public and private Fossil repositories
  * [codebasehq.com](https://www.codebasehq.com/) — One free project with 100 MB space and 2 users
  * [codeberg.org](https://codeberg.org/) - Unlimited public and private Git repos
  * [gitea.com](https://www.gitea.com/) - Unlimited public and private Git repos
  * [github.com](https://github.com/) — Unlimited public repositories and unlimited private repositories (with unlimited collaborators) with Pipelines for CI/CD
  * [gitlab.com](https://about.gitlab.com/) — Unlimited public and private Git repos with unlimited collaborators, with Pipelines for CI/CD, and 10 GB space per repo
  * [ionicframework.com](https://ionicframework.com/appflow) - Repo and tools to develop applications with Ionic, also you have an ionic repo
  * [NotABug](https://notabug.org) — NotABug.org is a free-software code collaboration platform for freely licensed projects, Git-based
  * [perforce.com](https://www.perforce.com/products/helix-teamhub) — Free 1GB Cloud and  Git, Mercurial, or SVN repositories.
  * [pijul.com](https://pijul.com/) - Unlimited free and open source distributed version control system. Its distinctive feature is to be based on a sound theory of patches, which makes it easy to learn and use, and really distributed. Solves many problems of git/hg/svn/darcs.
  * [plasticscm.com](https://plasticscm.com/) — Free for individuals, OSS and nonprofit organizations
  * [projectlocker.com](https://projectlocker.com) — One free private project (Git and Subversion) with 50 MB space
  * [savannah.gnu.org](https://savannah.gnu.org/) - Serves as a collaborative software development management system for free Software projects (for GNU Projects)
  * [savannah.nongnu.org](https://savannah.nongnu.org/) - Serves as a collaborative software development management system for free Software projects (for non-GNU projects)

## APIs, Data and ML

  * [algorithmia.com](https://algorithmia.com/) — Host algorithms for free. Includes free monthly allowance for running algorithms. Now with CLI support
  * [Apify](https://www.apify.com/) — Web scraping and automation platform that lets you create an API extracting websites data. Free tier with 10k monthly crawls and 7 days data retention.
  * [Beeceptor](https://beeceptor.com) - Mock a rest API in seconds, fake API response and much more. Free 50 requests per day, public dashboard, open endpoints (anyone having link to the dashboard can view requests and responses).
  * [bigml.com](https://bigml.com/) — Hosted machine learning algorithms. Unlimited free tasks for development, limit of 16 MB data/task
  * [Calendarific](https://calendarific.com) - Enterprise-grade Public holiday API service for over 200 countries. Free plan includes 1000 calls per month.
  * [Clarifai](https://www.clarifai.com) — Image API for custom face recognition and detection. Able to train AI models. Free plan has 5000 calls per month.
  * [Colaboratory](https://colab.research.google.com) — Free web-based Python notebook environment with Nvidia Tesla K80 GPU.
  * [CurrencyScoop](https://currencyscoop.com) - Realtime currency data API for fintech apps. Free plan includes 5000 calls per month.
  * [Datapane](https://datapane.com) - API for building interactive reports in Python and deploying Python scripts and Jupyter Notebooks as self-service tools.
  * [DB Designer](https://www.dbdesigner.net/) — Cloud based Database schema design and modeling tool with a free starter plan of 2 Database models and 10 tables per model.
  * [Diggernaut](https://www.diggernaut.com/) — Cloud based web scraping and data extraction platform for turning any website to the dataset or to work with it as with an API. Free plan includes 5K page requests monthly.
  * [dominodatalab.com](https://www.dominodatalab.com) — Data science with support for Python, R, Spark, Hadoop, MATLAB and others
  * [dreamfactory.com](https://dreamfactory.com/) — Open source REST API backend for mobile, web, and IoT applications. Hook up any SQL/NoSQL database, file storage system, or external service and it instantly creates a comprehensive REST API platform with live documentation, user management,...
  * [ETF Data API](https://etf-data.com/) - Quality European ETF, ETN and ETC data, updated daily. The API offers complete overview including sector, country, factor, dividend yield and valuations. Additionally basic information such as domicile, followed index, asset class, fee, currency, replication method, distribution type and frequency. 50 free API calls per day. 
  * [ExtendsClass](https://extendsclass.com/rest-client-online.html) - Free web-based HTTP client to send HTTP requests.
  * [FraudLabs Pro](https://www.fraudlabspro.com) — Screen an order transaction for credit card payment fraud. This REST API will detect all possible fraud traits based on the input parameters of an order. Free Micro plan has 500 transactions per month.
  * [FreeGeoIP.app](https://freegeoip.app/) - Completely free Geo IP information (JSON, CSV, XML). No registration required, 15000 queries per hour rate limit.
  * [GeoDataSource](https://www.geodatasource.com) — Location search service lookup for city name by using latitude and longitude coordinate. Free API queries up to 500 times per month.
  * [Hoppscotch](https://hoppscotch.io) - A free, fast, and beautiful API request builder.
  * [Invantive Cloud](https://cloud.invantive.com/) — Access over 70 (cloud)platforms such as Exact Online, Twinfield, ActiveCampaign or Visma using Invantive SQL or OData4 (typically Power BI or Power Query). Includes data replication and exchange. Free plan for developers and implementation consultants. Free for specific platforms with limitations in data volumes.
  * [IP Geolocation](https://ipgeolocation.io/) — IP Geolocation API - Forever free plan for developers with 30k requests per month (1k/day) limit.
  * [IP2Location](https://www.ip2location.com) — Freemium IP geolocation service. LITE database is available for free download. Import the database in server and perform local query to determine city, coordinates and ISP information.
  * [IPinfo](https://ipinfo.io/) — Fast, accurate, and free (up to 100k/month) IP address data API. Offers APIs with details on geolocation, companies, carriers, IP ranges, domains, abuse contacts, and more. All paid APIs can be trialed for free.
  * [IPList](https://www.iplist.cc) — Lookup details about any IP address, such as Geo IP information, tor addresses, hostnames and ASN details. Free for personal and business users.
  * [BigDataCloud](https://www.bigdatacloud.com/) - Provides fast, accurate and free (Unlimited or up to 10K-50K/month) APIs for modern web like IP Geolocation, Reverse Geocoding, Networking Insights, Email and Phone Validation, Client Info and more.
  * [IPTrace](https://iptrace.io) — An embarrassingly simple API that provides reliable and useful IP geolocation data for your business.
  * [konghq.com/](https://konghq.com/) — API Marketplace and powerful tools for private and public APIs. With the free tier, some features are limited such as monitoring, alerting and support
  * [MailboxValidator](https://www.mailboxvalidator.com) — Email verification service using real mail server connection to confirm valid email. Free API plan has 300 verifications per month.
  * [microlink.io](https://microlink.io/) – It turns any website into data such as metatags normalization, beauty link previews, scraping capabilities or screenshots as a service. 100 reqs/day every day free.
  * [monkeylearn.com](https://monkeylearn.com/) — Text analysis with machine learning, free 300 queries/month
  * [myfakeapi.com](https://myfakeapi.com) — Free serverless API mocking service for developers
  * [microenv.com](https://microenv.com) —  Create fake REST API for developers with possibility to generate code and app in docker container.
  * [OCR.Space](https://ocr.space/) — An OCR API which parses image and pdf files returning the text results in JSON format. 25,000 requests per month free.
  * [OpenAPI3 Designer](https://interaction-design.co.za/openapidesigner/) — Visually create Open API 3 definitions for free
  * [parsehub.com](https://parsehub.com/) — Extract data from dynamic sites, turn dynamic websites into APIs, 5 projects free
  * [Pixela](https://pixe.la/) - Free daystream database service. All operations are performed by API. Visualization with heat maps and line graphs is also possible.
  * [Postbacks](https://postbacks.io/) - Request HTTP callbacks for a later time. 8,000 free requests on signup.
  * [Postman](https://postman.com) — Simplify workflows and create better APIs – faster – with Postman, a collaboration platform for API development. Use the Postman App for free forever. Postman cloud features are also free forever with certain limits.
  * [ProxyCrawl](https://proxycrawl.com/) — Crawl and scrape websites without the need of proxies, infrastructure or browsers. We solve captchas for you and prevent you being blocked. The first 1000 calls are free of charge.
  * [Releaseflags](https://releaseflags.com) - Feature Flags should be available for every developer at a low-cost. Releaseflags offers free releaseflags for single developers and a low-cost plan for startups.
  * [RequestBin.com](https://requestbin.com) — Create a free endpoint to which you can send HTTP requests. Any HTTP requests sent to that endpoint will be recorded with the associated payload and headers so you can observe requests from webhooks and other services.
  * [restlet.com](https://restlet.com/products/apispark/) — APISpark enables any API, application or data owner to become an API provider in minutes via an intuitive browser interface
  * [ROBOHASH](https://robohash.org/) - Web service to generate unique (cool :) images from any text.
  * [Scraper.AI](https://scraper.ai) - SaaS that turns any website into a consumable API for you to build on. Free 50 extractions and 10000 API calls / month.
  * [Scraper API](https://www.scraperapi.com/) — Cloud based web scraping API handles proxies, browsers, and CAPTCHAs. Scrape any web page with a simple API call. Get started with 1000 free API calls/month.  
  * [ScrapingAnt](https://scrapingant.com/) — Headless Chrome scraping API and free checked proxies service. Javascript rendering, premium rotating proxies, CAPTCHAs avoiding. Free plans available.
  * [ScraperBox](https://scraperbox.com/) — Undetectable web scraping API using real Chrome browsers and proxy rotation. Use a simple API call to scrape any web page. Free plan has 1000 requests per month.
  * [ScrapingDog](https://scrapingdog.com/) — Scrapingdog handles millions of proxies, browsers and CAPTCHAs to provide you with HTML of any web page in a single API call. It also provides Web Scraper for Chrome & Firefox and a software for instant scraping demand. Free plans available.
  * [scrapinghub.com](https://scrapinghub.com) — Data scraping with visual interface and plugins. Free plan includes unlimited scraping on a shared server
  * [ScrapingNinja](https://www.scrapingninja.co/) — Handle JS rendering, Chrome Headless, Proxy rotation and CAPTCHAs solving all in one place. The first 1000 are free of charge, no credit card required.
  * [Sheetson](https://sheetson.com) - Instantly turn any Google Sheets into RESTful API. Free plan available.
  * [shrtcode API](https://shrtco.de/docs) - Free URL Shortening API without authorisation and no request limits
  * [Sofodata](https://www.sofodata.com/) - Create secure RESTful APIs from CSV files. Upload a CSV file and instantly access the data via its API allowing faster application development. Free plan includes 2 APIs and 2,500 API calls per month. No credit card required.
  * [tamber](https://tamber.com) — Put deep-learning powered recommendations in your app. Free 5k monthly active users.
  * [Time Door](https://timedoor.io) - A time series analysis API
  * [Vattly](https://vattly.com/) - Highly available, fast and secure VAT validation API, that provides full European Union coverage. 10 free API calls per day.
  * [Webhook.site](https://webhook.site) - Easily test HTTP webhooks with this handy tool that displays requests instantly.
  * [wit.ai](https://wit.ai/) — NLP for developers
  * [wolfram.com](http://wolfram.com/language/) — Built-in knowledge-based algorithms in the cloud
  * [wrapapi.com](https://wrapapi.com/) — Turn any website into a parameterized API. 30k API calls per month
  * [Zenscrape](https://zenscrape.com/web-scraping-api) — Web scraping API with headless browsers, residentials IPs and simple pricing. 1000 free API calls/month, extra free credits for students and non-profits
  * [ip-api](https://ip-api.com) — IP Geolocation API, Free for non-commercial use, no API key required, limited to 45 req/minute from the same IP address for the free plan.
  * [WebScraping.AI](https://webscraping.ai) - Simple Web Scraping API with built-in parsing, Chrome rendering and proxies. 5000 free API calls per month.
  * [Zipcodebase](https://zipcodebase.com) - Free Zip Code API, access to Worldwide Postal Code Data. 10000 free requests/month.
  * [EVA](http://eva.pingutil.com/) - Free email vaidator API, which helps to identify whether an email is dispsable and having valid MX records.

## Artifact Repos

 * [bintray.com](https://bintray.com/) — JFrog Bintray hosts Open Source projects for free, and supports Docker, Maven, NuGet, npm, Debian, RPM, Conan, Vagrant, Opkg, yum, and also home to [JCenter](https://bintray.com/bintray/jcenter) the most comprehensive collection of Maven artifacts.
 * [central.sonatype.org](https://central.sonatype.org) — The default artifact repository for Apache Maven, SBT and other build systems.
 * [cloudrepo.io](https://cloudrepo.io) - Cloud based, private and public, Maven and PyPi repositories. Free for open source projects.
 * [cloudsmith.io](https://cloudsmith.io) — Simple, secure and centralised repository service for Java/Maven, RedHat, Debian, Python, Ruby, Vagrant +more. Free tier + free for open source.
 * [jitpack.io](https://jitpack.io/) — Maven repository for JVM and Android projects on GitHub, free for public projects.
 * [packagecloud.io](https://packagecloud.io) — Easy to use repository hosting for: Maven, RPM, DEB, PyPi and RubyGem packages (has free tier).
 * [repsy.io](https://repsy.io) — 1 GB Free private/public Maven Repository.

## Tools for Teams and Collaboration

  * [Bitwarden](https://bitwarden.com) — The easiest and safest way for individuals, teams, and business organizations to store, share, and sync sensitive data.
  * [cally.com](https://cally.com/) — Find the perfect time and date for a meeting. Simple to use, works great for small and large groups.
  * [Discord](https://discordapp.com/) — Chat with public/private Rooms & VoIP Service. Free for unlimited users.
  * [evernote.com](https://evernote.com/) — Tool for organizing information. Share your notes and work together with others
  * [featurepeek.com](https://featurepeek.com) - Cloud provider-agnostic front-end feature environments with team collaboration tools built-in. Works with static and Dockerized front-ends. Free for public repositories.
  * [Filestash](https://www.filestash.app) — A Dropbox-like file manager that connects to a range of protocols and platforms: S3, FTP, SFTP, Minio, Git, WebDAV, Backblaze, LDAP and more.
  * [flock.com](https://flock.com) — A faster way for your team to communicate. Free Unlimited Messages, Channels, Users, Apps & Integrations
  * [flowdock.com](https://www.flowdock.com/) — Chat and inbox, free for teams up to 5
  * [GitDuck](https://gitduck.com/) — Private live coding and remote pair programming for distributed teams. Open-source tool
  * [gitter.im](https://gitter.im/) — Chat, for GitHub. Unlimited public and private rooms, free for teams up to 25
  * [hangouts.google.com](https://hangouts.google.com/) — One place for all your conversations, for free, need a Google account
  * [helplightning.com](https://www.helplightning.com/) — Help over video with augmented reality. Free without analytics, encryption, support
  * [helpmonks.com](https://helpmonks.com/) — Shared inbox for teams, free for Open Source and nonprofit organizations
  * [ideascale.com](https://ideascale.com/) — Allow clients to submit ideas and vote, free for 25 members in 1 community
  * [Igloo](https://www.igloosoftware.com/) — Internal portal for sharing documents, blogs and calendars etc. Free for up to 10 users.
  * [Keybase](https://keybase.io/) — Keybase is a cool FOSS alternative to Slack, it keeps everyone's chats and files safe, from families to communities to companies.
  * [Google Meet](https://meet.google.com/) — Use Google Meet for your business's online video meeting needs. Meet provides secure, easy-to-join online meetings.
  * [meet.jit.si](https://meet.jit.si/) — One click video conversations, screen sharing, for free
  * [Microsoft Teams](https://products.office.com/microsoft-teams/free) — Microsoft Teams is a chat-based digital hub that brings conversations, content, and apps together in one place all from a single experience. Free for up to 300 users.
  * [Miro](https://miro.com/) - Scalable, secure, cross-device and enterprise-ready team collaboration whiteboard for distributed teams. With freemium plan.
  * [Notion](https://www.notion.so/) - Notion is a note-taking and collaboration application with markdown support that also integrates tasks, wikis, and databases. The company describes the app as an all-in-one workspace for note-taking, project management and task management. In addition to cross-platform apps, it can be accessed via most web browsers.
  * [Pendulums](https://pendulums.io/) - Pendulums is a free time tracking tool which helps you to manage your time in a better manner with an easy to use interface and useful statistics.
  * [Raindrop.io](https://raindrop.io) - Private and secure bookmarking app for macOS, Windows, Android, iOS and Web. Free Unlimited Bookmarks and Collaboration.
  * [element.io](https://element.io/) — A decentralized and open source communication tool built on Matrix. Group chats, direct messaging, encrypted file transfers, voice and video chats, and easy integration with other services.
  * [Rocket.Chat](https://rocket.chat/) - Shared inbox for teams, secure, unlimited and open source.
  * [seafile.com](https://www.seafile.com/) — Private or cloud storage, file sharing, sync, discussions. Private version is full. Cloud version has just 1 GB
  * [slack.com](https://slack.com/) — Free for unlimited users with some feature limitations
  * [Spectrum](https://spectrum.chat/) - Create public or private communities for free.
  * [StatusPile](https://www.statuspile.com/) - A status page of status pages. Track the status pages of your upstream providers.
  * [Tadum](https://tadum.app) - Meeting agenda and minutes app designed for recurring meetings, free for teams up to 10
  * [talky.io](https://talky.io/) — Free group video chat. Anonymous. Peer‑to‑peer. No plugins, signup, or payment required
  * [Tefter](https://tefter.io) - Bookmarking app with a powerful Slack integration. Free for open-source teams.
  * [twist.com](https://twist.com) — An asynchronous-friendly team communication app where conversations stay organized and on-topic. Free and Unlimited plans available. Discounts provided for eligible teams.
  * [typetalk.com](https://www.typetalk.com/) — Share and discuss ideas with your team through instant messaging on the web or on your mobile
  * [Tugboat](https://tugboat.qa) - Preview every pull request, automated and on-demand. Free for all, complimentary Nano tier for non-profits.
  * [whereby.com](https://whereby.com/) — One click video conversations, for free (formerly known as appear.in)
  * [userforge.com](https://userforge.com/) - Interconnected online personas, user stories and context mapping.  Helps keep design and dev in sync, free for up to 3 personas and 2 collaborators.
  * [wistia.com](https://wistia.com/) — Video hosting with viewer analytics, HD video delivery and marketing tools to help understand your visitors, 25 videos and Wistia branded player
  * [yammer.com](https://www.yammer.com/) — Private social network standalone or for MS Office 365. Free with a bit less admin tools and user management features
  * [zoom.us](https://zoom.us/) — Secure Video and Web conferencing, add-ons available. Free limited to 40 minutes


## CMS

  * [Cosmic](https://www.cosmicjs.com/) — Headless CMS and API toolkit. Free personal plans for developers.
  * [acquia.com](https://www.acquia.com/) — Hosting for Drupal sites. Free tier for developers. Free development tools (such as Acquia Dev Desktop) also available
  * [contentful.com](https://www.contentful.com/) — Headless CMS. Content management and delivery APIs in the cloud. Comes with one free micro space that includes 10 users, 5000 records, 24 Content Types, 2 locales.
  * [Prismic](https://www.prismic.io/) — Headless CMS. Content management interface with fully hosted and scalable API. The Community Plan provides 1 user with unlimited API calls, documents, custom types, assets, and locales. Everything that you need for your next project. Bigger free plans available for Open Content/Open Source projects.
  * [sanity.io](https://www.sanity.io/) – Hosted backend for structured content with customizable MIT licensed editor built with React. Unlimited projects. 3 users, 2 datasets, 500k API CDN requests, 5GB assets for free per project
  * [kontent.ai](https://www.kontent.ai) - A Content-as-a-Service platform that gives you all the headless CMS benefits while empowering marketers at the same time. Developer plan provides 2 users with unlimited projects with 2 environments for each, 500 content items, 2 languages with Delivery and Management API, and Custom elements support. Larger plans available to meet your needs.
  * [Forestry.io/](https://forestry.io/) — Headless CMS. Give your editors the power of Git. Create and edit Markdown-based content with ease. Comes with three free sites that includes 3 editors, Instant Previews. Integrates with blogs hosted on Netlify/GitHubpages/ elsewhere

## Code Quality

  * [beanstalkapp.com](https://beanstalkapp.com/) — A complete workflow to write, review and deploy code), free account for 1 user and 1 repository with 100 MB of storage
  * [browserling.com](https://www.browserling.com/) — Live interactive cross-browser testing, free only 3 minutes sessions with MS IE 9 under Vista at 1024 x 768 resolution
  * [codacy.com](https://www.codacy.com/) — Automated code reviews for PHP, Python, Ruby, Java, JavaScript, Scala, CSS and CoffeeScript, free for unlimited public and private repositories
  * [Codeac.io](https://www.codeac.io/infrastructure-as-code.html?ref=free-for-dev) - Automated Infrastructure as Code review tool for DevOps integrates with GitHub, Bitbucket and GitLab (even self-hosted). In addition to standard languages, it analyzes also Ansible, Terraform, CloudFormation, Kubernetes, and more. (open-source free)
  * [codeclimate.com](https://codeclimate.com/) — Automated code review, free for Open Source and unlimited organisation-owned private repos (up to 4 collaborators). Also free for students and institutions.
  * [codecov.io](https://codecov.io/) — Code coverage tool (SaaS), free for Open Source and 1 free private repo
  * [codescene.io](https://codescene.io/) - CodeScene prioritizes technical debt based on how the developers work with the code and visualizes organizational factors like team coupling and system mastery. Free for Open Source.
  * [coveralls.io](https://coveralls.io/) — Display test coverage reports, free for Open Source
  * [dareboost](https://dareboost.com) - 5 free analysis report for web performance, accessibility, security each month
  * [deepcode.ai](https://www.deepcode.ai) — DeepCode finds bugs, security vulnerabilities, performance and API issues based on AI. DeepCode's speed of analysis allow us to analyse your code in real time and deliver results when you hit the save button in your IDE. Supported languages are Java, C/C++, JavaScript, Python, and TypeScript. Integrations with GitHub, BitBucket and Gitlab. Free for open source and private repos, free up to 30 developers.
  * [deepscan.io](https://deepscan.io) — Advanced static analysis for automatically finding runtime errors in JavaScript code, free for Open Source
  * [DeepSource](https://deepsource.io/) - DeepSource continuously analyzes source code changes, finds and fixes issues categorized under security, performance, anti-patterns, bug-risks, documentation and style. Native integration with GitHub, GitLab and Bitbucket.
  * [gerrithub.io](https://review.gerrithub.io/) — Gerrit code review for GitHub repositories for free
  * [gocover.io](https://gocover.io/) — Code coverage for any [Go](https://golang.org/) package
  * [goreportcard.com](https://goreportcard.com/) — Code Quality for Go projects, free for Open Source
  * [gtmetrix.com](https://gtmetrix.com/) — Reports and thorough recommendations to optimize websites
  * [hiberly.com](https://hiberly.com) - Tech debt toolkit for developers - grabs feedback from engineers after each merge, then aggregates this to quantify and highlight tech debt in the codebase. Free for use in retrospectives for up to 12 months.
  * [houndci.com](https://houndci.com/) — Comments on GitHub commits about code quality, free for Open Source
  * [Imgbot](https://github.com/marketplace/imgbot) — Imgbot is a friendly robot that optimizes your images and saves you time. Optimized images mean smaller file sizes without sacrificing quality. It's free for open source.
  * [resmush.it](https://resmush.it) — reSmush.it is a FREE API that provides image optimization. reSmush.it has been implemented on the most common CMS such as Wordpress, Drupal or Magento. reSmush.it is the most used image optimization API with more than 7 billions images already treated, and is still Free of charge.
  * [insight.sensiolabs.com](https://insight.sensiolabs.com/) — Code Quality for PHP/Symfony projects, free for Open Source
  * [lgtm.com](https://lgtm.com) — Continuous security analysis for Java, Python, JavaScript, TypeScript, C#, C and C++, free for Open Source
  * [reviewable.io](https://reviewable.io/) — Code review for GitHub repositories, free for public or personal repos
  * [scan.coverity.com](https://scan.coverity.com/) — Static code analysis for Java, C/C++, C# and JavaScript, free for Open Source
  * [scrutinizer-ci.com](https://scrutinizer-ci.com/) — Continuous inspection platform, free for Open Source
  * [shields.io](https://shields.io) — Quality metadata badges for open source projects
  * [sonarcloud.io](https://sonarcloud.io) — Automated source code analysis for Java, JavaScript, C/C++, C#, VB.NET, PHP, Objective-C, Swift, Python, Groovy and even more languages, free for Open Source
  * [tachikoma.io](https://tachikoma.io/) — Dependency Update for Ruby, Node.js, Perl projects, free for Open Source
  * [Typo CI](https://github.com/marketplace/typo-ci) — Typo CI reviews your Pull Requests and commits for spelling mistakes, free for Open Source.
  * [webceo.com](https://www.webceo.com/) — SEO tools but with also code verifications and different type of advices
  * [zoompf.com](https://zoompf.com/) — Fix the performance of your web sites, detailed analysis

## Code Search and Browsing

  * [codota.com](https://www.codota.com/) — Codota helps developers create better software, faster by providing insights learned from all the code in the world. Plugin available.
  * [libraries.io](https://libraries.io/) — Search and dependency update notifications for 32 different package managers, free for open source
  * [searchcode.com](https://searchcode.com/) — Comprehensive text-based code search, free for Open Source
  * [sourcegraph.com](https://about.sourcegraph.com/) — Java, Go, Python, Node.js, etc., code search/cross-references, free for Open Source
  * [tickgit.com](https://www.tickgit.com/) — Surfaces `TODO` comments (and other markers) to identify areas of code worth returning to for improvement.

## CI and CD

  * [AccessLint](https://github.com/marketplace/accesslint) — AccessLint brings automated web accessibility testing into your development workflow. It's free for open source and education purposes.
  * [appcircle.io](https://appcircle.io) — Automated mobile CI/CD/CT for iOS and Android with online device emulators. 20 minutes build timeout (60 mins for Open Source) with single concurrency for free.
  * [appveyor.com](https://www.appveyor.com/) — CD service for Windows, free for Open Source
  * [Azure Pipelines](https://azure.microsoft.com/services/devops/pipelines/) — 10 free parallel jobs with unlimited minutes for open source for Linux, macOS, and Windows
  * [bitrise.io](https://www.bitrise.io/) — A CI/CD for mobile apps, native or hybrid. With 200 free builds/month 10 min build time and two team members. OSS projects get 45 min build time, +1 concurrency and unlimited team size.
  * [buddy.works](https://buddy.works/) — A CI/CD with 5 free projects and 1 concurrent runs (120 executions/month)
  * [buddybuild.com](https://www.buddybuild.com/) — Build, deploy and gather feedback for your iOS and Android apps in one seamless, iterative system
  * [circleci.com](https://circleci.com/) — Free for one concurrent build
  * [codefresh.io](https://codefresh.io) — Free-for-Life plan: 1 build, 1 environment, shared servers, unlimited public repos
  * [codeship.com](https://codeship.com/) — 100 private builds/month, 5 private projects, unlimited for Open Source
  * [deployhq.com](https://www.deployhq.com/) — 1 project with 10 daily deployments (30 build minutes/month)
  * [gitlab.com](https://about.gitlab.com/product/continuous-integration/) — Create pipelines directly from Git repositories using GitLab's CI service.  2,000min/mo
  * [ligurio/awesome-ci](https://github.com/ligurio/awesome-ci) — Comparison of Continuous Integration services
  * [semaphoreci.com](https://semaphoreci.com/) — Free for Open Source, 100 private builds per month
  * [shippable.com](https://app.shippable.com/) — 150 private builds/month, free for 1 build container, private and public repos
  * [stackahoy.io](https://stackahoy.io) — 100% free. Unlimited deployments, branches and builds
  * [styleci.io](https://styleci.io/) — Public GitHub repositories only
  * [travis-ci.org](https://travis-ci.org/) — Free for public GitHub repositories
  * [cirrus-ci.org](https://cirrus-ci.org) - Free for public GitHub repositories
  * [drone](https://cloud.drone.io/) - Drone Cloud enables developers to run Continuous Delivery pipelines across multiple architectures - including x86 and Arm (both 32 bit and 64 bit) - all in one place
  * [codemagic.io](https://codemagic.io/) - Free 500 build minutes/month

## Testing

  * [Applitools.com](https://applitools.com/) — smart visual validation for web, native mobile and desktop apps. Integrates with almost all automation solutions (like Selenium and Karma) and remote runners (Sauce Labs, Browser Stack). free for open source. A free tier for a single user with limited checkpoints per week.
  * [browserstack.com](https://www.browserstack.com/) — Manual and automated browser testing, [free for Open Source](https://www.browserstack.com/open-source?ref=pricing)
  * [checkbot.io](https://www.checkbot.io/) — Browser extension that tests if your website follows 50+ SEO, speed and security best practices. Free tier for smaller websites.
  * [crossbrowsertesting.com](https://crossbrowsertesting.com) - Manual, Visual, and Selenium Browser Testing in the cloud - [free for Open Source](https://crossbrowsertesting.com/open-source)
  * [cypress.io](https://www.cypress.io/) - Fast, easy and reliable testing for anything that runs in a browser. Cypress Test Runner is always free and open source with no restrictions and limitations. Cypress Dashboard is free for open source projects for up to 5 users.
  * [everystep-automation.com](https://www.everystep-automation.com/) — Records and replays all steps made in a web browser and creates scripts,... free with fewer options
  * [Gremlin](https://www.gremlin.com/gremlin-free-software) — Gremlin's Chaos Engineering tools allow you to safely, securely, and simply inject failure into your systems to find weaknesses before they cause customer-facing issues. Gremlin Free provides access to Shutdown and CPU attacks on up to 5 hosts or containers.
  * [gridlastic.com](https://www.gridlastic.com/) — Selenium Grid testing with free plan up to 4 simultaneous selenium nodes/10 grid starts/4,000 test minutes/month
  * [percy.io](https://percy.io) - Add visual testing to any web app, static site, style guide, or component library.  10 team members, Demo app and unlimited projects, 5,000 snapshots / month.
  * [reflect.run](https://reflect.run) - Codeless automated tests for web apps. Tests can be scheduled in-app or executed from a CI/CD tool. Each test run includes a full video recording along with console and network logs. The free tier includes an unlimited number of saved tests, with 25 test runs per month and up to 3 users.
  * [saucelabs.com](https://saucelabs.com/) — Cross browser testing, Selenium testing and mobile testing, [free for Open Source](https://saucelabs.com/open-source)
  * [testingbot.com](https://testingbot.com/) — Selenium Browser and Device Testing, [free for Open Source](https://testingbot.com/open-source)
  * [tesults.com](https://www.tesults.com) — Test results reporting and test case management. Integrates with popular test frameworks. Open Source software developers, individuals, educators, and small teams getting started can request discounted and free offerings beyond basic free project.
  * [websitepulse.com](https://www.websitepulse.com/tools/) — Various free network and server tools.
  * [qase.io](https://qase.io) - Test management system for Dev and QA teams. Manage test cases, compose test runs, perform test runs, track defects and measure impact. The free tier includes all core features, with 500Mb available for attachments and up to 3 users.

## Security and PKI

  * [alienvault.com](https://www.alienvault.com/open-threat-exchange/reputation-monitor) — Uncovers compromised systems in your network
  * [auth0.com](https://auth0.com/) — Hosted free for development SSO. Up to 2 social identity providers for closed-source projects.
  * [bitninja.io](https://bitninja.io/) — Botnet protection through a blacklist, free plan only reports limited information on each attack
  * [cloudsploit.com](https://cloudsploit.com/) — Amazon Web Services (AWS) security and compliance auditing and monitoring
  * [CodeNotary.io](https://www.codenotary.io/) — Open Source platform with indelible proof to notarize code, files, directories or container
  * [crypteron.com](https://www.crypteron.com/) — Cloud-first, developer-friendly security platform prevents data breaches in .NET and Java applications
  * [Dependabot](https://dependabot.com/) Automated dependency updates for Ruby, JavaScript, Python, PHP, Elixir, Rust, Java (Maven and Gradle), .NET, Go, Elm, Docker, Terraform, Git Submodules and GitHub Actions.
  * [duo.com](https://duo.com/) — Two-factor authentication (2FA) for website or app. Free for 10 users, all authentication methods, unlimited, integrations, hardware tokens
  * [Firebase Auth](https://firebase.google.com/products/auth/) — Free end-to-end identity solution, email and password accounts, Google, Twitter, Facebook, GitHub login, phone auth (up to 10k/month), and more.
  * [foxpass.com](https://www.foxpass.com/) — Hosted LDAP and RADIUS. Easy per-user logins to servers, VPNs and wireless networks. Free for 10 users
  * [globalsign.com](https://www.globalsign.com/en/ssl/ssl-open-source/) — Free SSL certificates for Open Source
  * [Have I been pwned?](https://haveibeenpwned.com) — REST API for fetching the information on the breaches.
  * [Internet.nl](https://internet.nl) — Test for modern Internet Standards like IPv6, DNSSEC, HTTPS, DMARC, STARTTLS and DANE
  * [Jumpcloud](https://jumpcloud.com/) — Provides directory as a service similar to Azure AD, user management, single sign-on, and RADIUS authentication. Free for up to 10 users.
  * [keychest.net](https://keychest.net) - SSL expiry management and cert purchase with an integrated CT database
  * [letsencrypt.org](https://letsencrypt.org/) — Free SSL Certificate Authority with certs trusted by all major browsers
  * [LoginRadius](https://www.loginradius.com/) — Managed User Authentication service for free. Email registartion and 3 social providers.
  * [logintc.com](https://www.logintc.com/) — Two-factor authentication (2FA) by push notifications, free for 10 users, VPN, Websites and SSH
  * [meterian.io](https://www.meterian.io/) - Monitor Java, Javascript, .NET, Scala, Ruby and NodeJS projects for security vulnerabilities in dependencies. Free for one private project, unlimited projects for open source.
  * [Mozilla Observatory](https://observatory.mozilla.org/) — Find and fix security vulnerabilities in your site.
  * [Okta](https://developer.okta.com/) — User management, authentication and authorization. Free for up to 1000 monthly active users.
  * [onelogin.com](https://www.onelogin.com/) — Identity as a Service (IDaaS), Single Sign-On Identity Provider, Cloud SSO IdP, 3 company apps and 5 personal apps, unlimited users
  * [opswat.com](https://www.opswat.com/) — Security Monitoring of computers, devices, applications, configurations,... Free 25 users and 30 days history
  * [ponycheckup.com](https://www.ponycheckup.com/) — An automated security checkup tool for Django websites
  * [Protectumus](https://protectumus.com) - Free website security check, site antivirus and server firewall (WAF). Email and SMS notifications for registered users.
  * [pyup.io](https://pyup.io) — Monitor Python dependencies for security vulnerabilities and update them automatically. Free for one private project, unlimited projects for open source.
  * [qualys.com](https://www.qualys.com/community-edition) — Find web app vulnerabilities, audit for OWASP Risks
  * [report-uri.io](https://report-uri.io/) — CSP and HPKP violation reporting
  * [ringcaptcha.com](https://ringcaptcha.com/) — Tools to use phone number as id, available for free
  * [Shieldfy](https://shieldfy.io) — Web application firewall and vulnerability detection for developers, free plan up to 100k requests per month.
  * [snyk.io](https://snyk.io) — Can find and fix known security vulnerabilities in your open source dependencies. Unlimited tests and remediation for open source projects. Limited to 200 tests/month for your private projects.
  * [Sqreen](https://www.sqreen.com/) — Application security monitoring and protection (RASP, WAF and more) for web applications and APIs. Free for 1 app and 3 million requests.
  * [ssllabs.com](https://www.ssllabs.com/ssltest/) — Very deep analysis of the configuration of any SSL web server
  * [Sucuri SiteCheck](https://sitecheck.sucuri.net) - Free website security check and malware scanner
  * [threatconnect.com](https://threatconnect.com) — Threat intelligence: It is designed for individual researchers, analysts and organizations who are starting to learn about cyber threat intelligence. Free up to 3 Users
  * [tinfoilsecurity.com](https://www.tinfoilsecurity.com/) — Automated vulnerability scanning. Free plan allows weekly XSS scans
  * [Virgil Security](https://virgilsecurity.com/) — Tools and services for implementing end-to-end encryption, database protection, IoT security and more in your digital solution. Free for applications with up to 250 users.
  * [Virushee](https://virushee.com/) — Privacy-oriented file/data scanning powered by hybrid heuristic and AI-assisted engine. Possible to use internal dynamic sandbox analysis. Limited to 50MB per file upload

## Management System

  * [bitnami.com](https://bitnami.com/) — Deploy prepared apps on IaaS. Management of 1 AWS micro instance free
  * [jamf.com](https://www.jamf.com/) —  Device management for iPads, iPhones and Macs, 3 devices free
  * [moss.sh](https://moss.sh) - Help developers deploy and manage their web apps and servers. Free up to 25 git deployments per month
  * [runcloud.io](https://runcloud.io/) - Server management focusing mainly on PHP projects. Free for up to 1 server.

## Messaging

  * [cloudamqp.com](https://www.cloudamqp.com/) — RabbitMQ as a Service. Little Lemur plan: max 1 million messages/month, max 20 concurrent connections, max 100 queues, max 10,000 queued messages, multiple nodes in different AZ's
  * [pusher.com](https://pusher.com/) — Realtime messaging service. Free for up to 100 simultaneous connections and 200,000 messages/day
  * [scaledrone.com](https://www.scaledrone.com/) — Realtime messaging service. Free for up to 20 simultaneous connections and 100,000 events/day
  * [synadia.com](https://synadia.com/ngs) — [NATS.io](https://nats.io) as a service. Global, AWS, GCP, and Azure. Free forever with 4k msg size, 50 active connections and 5GB of data per month.
  * [cloudkarafka.com](https://www.cloudkarafka.com/) - Free Shared Kafka cluster, up to 5 topics, 10MB data per topic and 28 days of data retention.


## Log Management

  * [bugfender.com](https://bugfender.com/) — Free up to 100k log lines/day with 24 hours retention
  * [humio.com](https://www.humio.com/) — Free up to 2 GB/day with 7 days retention
  * [logentries.com](https://logentries.com/) — Free up to 5 GB/month with 7 days retention
  * [loggly.com](https://www.loggly.com/) — Free for a single user, see the lite option
  * [logz.io](https://logz.io/) — Free up to 3 GB/day, 3 days retention
  * [papertrailapp.com](https://papertrailapp.com/) — 48 hours search, 7 days archive, 100 MB/month
  * [sematext.com](https://sematext.com/logsene) — Free up to 500 MB/day, 7 days retention
  * [splunk.com](https://www.splunk.com) - Free for a single user, 500 MB/day
  * [sumologic.com](https://www.sumologic.com/) — Free up to 500 MB/day, 7 days retention

## Translation Management

  * [crowdin.com](https://crowdin.com/) — Unlimited projects, unlimited strings and collaborators for Open Source
  * [lingohub.com](https://lingohub.com/) — Free up to 3 users, always free for Open Source
  * [localizely.com](https://localizely.com/) — Free for Open Source
  * [Loco](https://localise.biz/) — Free up to 2000 translations, Unlimited translators, 10 languages/project, 1000 translatable assets/project
  * [oneskyapp.com](https://www.oneskyapp.com/) — Limited free edition for up to 5 users, free for Open Source
  * [POEditor](https://poeditor.com/) — Free up to 1000 strings
  * [transifex.com](https://www.transifex.com/) — Free for Open Source
  * [webtranslateit.com](https://webtranslateit.com/) — Free up to 500 strings
  * [weblate.org](https://weblate.org/) — It's free for libre projects up to 10,000 string source for the free tier, and Unlimited Self-hosted on-premises.

## Monitoring

  * [apimetrics.io](https://apimetrics.io/) — Automated API Performance Monitoring, Testing and Analytics. Free Plan, manually make API calls and Run from their West Coast servers
  * [appdynamics.com](https://www.appdynamics.com/) — Free for 24 hours metrics, application performance management agents limited to one Java, one .NET, one PHP and one Node.js
  * [appneta.com](https://www.appneta.com/) — Free with 1-hour data retention
  * [assertible.com](https://assertible.com) — Automated API testing and monitoring. Free plans for teams and individuals.
  * [bearer.sh](https://www.bearer.sh) - Automatically Monitor API Requests, Track Performance, Detect Anomalies and Fix Issues on your critical API Usage. Install the Bearer Agent for Free with 1 line of code.
  * [blackfire.io](https://blackfire.io/) — Blackfire is the SaaS-delivered Application Performance Solution. Free Hacker plan (PHP only)
  * [circonus.com](https://www.circonus.com/) — Free for 20 metrics
  * [cloudsploit.com](https://cloudsploit.com) — AWS security and configuration monitoring. Free: unlimited on-demand scans, unlimited users, unlimited stored accounts. Subscription: automated scanning, API access, etc.
  * [datadoghq.com](https://www.datadoghq.com/) — Free for up to 5 nodes
  * [deadmanssnitch.com](https://deadmanssnitch.com/) — Monitoring for cron jobs. 1 free snitch (monitor), more if you refer others to sign up
  * [elastic.co](https://www.elastic.co/solutions/apm) — Instant performance insights for JS developers. Free with 24 hours data retention
  * [freeboard.io](https://freeboard.io/) — Free for public projects. Dashboards for your Internet of Things (IoT) projects
  * [freshworks.com](https://www.freshworks.com/website-monitoring/) — Monitor 50 URLs at 1-minute interval with 10 Global locations and 5 Public status pages for Free
  * [ghostinspector.com](https://ghostinspector.com/) — Free website and web application monitoring. Single user, 100 test runs/month
  * [gitential.com](https://gitential.com) — Software Development Analytics platform. Free: unlimited public repositories, unlimited users, free trial for private repos. On-prem version available for enterprise.
  * [healthchecks.io](https://healthchecks.io) — Monitor your cron jobs and background tasks. Free for up to 20 checks.
  * [inspector.dev](https://www.inspector.dev) - A complete Real-Time monitoring dashboard in less than one minute with free forever tier.
  * [instrumentalapp.com](https://instrumentalapp.com) - Beautiful and easy-to-use application and server monitoring with up to 500 metrics and 3 hours of data visibility for free
  * [keychest.net/speedtest](https://keychest.net/speedtest) - Independent speed test and TLS handshake latency test against Digital Ocean
  * [letsmonitor.org](https://letsmonitor.org) - SSL monitoring, free for up to 5 monitors
  * [loader.io](https://loader.io/) — Free load testing tools with limitations
  * [nixstats.com](https://nixstats.com) - Free for one server. E-Mail Notifications, public status page, 60 second interval and more.
  * [nodequery.com](https://nodequery.com/) — Free basic server monitors up to 10 servers
  * [opsgenie.com](https://www.opsgenie.com/) — Powerful alerting and on-call management for operating always-on services. Free up to 5 users.
  * [paessler.com](https://www.paessler.com/) — Powerful infrastructure and network monitoring solution including alerting, strong visualization capabilities and basic reporting. Free up to 100 sensors.
  * [pagertree.com](https://pagertree.com/) - Simple interface for alerting and on-call management. Free up to 5 users.
  * [pingbreak.com](https://pingbreak.com/) — Modern uptime monitoring service. Check unlimited URLs and get downtime notifications via Discord, Slack or email.
  * [sematext.com](https://sematext.com/) — Free for 24 hours metrics, unlimited number of servers, 10 custom metrics, 500,000 custom metrics data points, unlimited dashboards, users, etc.
  * [sitemonki.com](https://sitemonki.com/) — Website, domain, Cron & SSL monitoring, 5 monitors in each category for free
  * [skylight.io](https://www.skylight.io/) — Free for first 100,000 requests (Rails only)
  * [speedchecker.xyz](https://probeapi.speedchecker.xyz/) — Performance Monitoring API, checks Ping, DNS, etc.
  * [stathat.com](https://www.stathat.com/) — Get started with 10 stats for free, no expiration
  * [statuscake.com](https://www.statuscake.com/) — Website monitoring, unlimited tests free with limitations
  * [thousandeyes.com](https://www.thousandeyes.com/) — Network and user experience monitoring. 3 locations and 20 data feeds of major web services free
  * [uptimerobot.com](https://uptimerobot.com/) — Website monitoring, 50 monitors free
  * [uptimetoolbox.com](https://uptimetoolbox.com/) — Free monitoring for 5 websites, 60 second intervals, public statuspage.
  * [zenduty.com](https://www.zenduty.com/) — End-to-end incident management, alerting, on-call management and response orchestration platform for network operations, site reliability engineering and DevOps teams. Free for upto 5 users.

## Crash and Exception Handling

  * [bugsnag.com](https://www.bugsnag.com/) — Free for up to 2,000 errors/month after the initial trial
  * [honeybadger.io](https://www.honeybadger.io) - Exception, uptime, and cron monitoring. Free for solo devs and open-source projects (12,000 errors/month).
  * [logrocket.io](https://www.logrocket.com) - Logging and session replay for javascript apps. Free for 1,000 sessions a month, 14 days retention
  * [rollbar.com](https://rollbar.com/) — Exception and error monitoring, free plan with 5,000 errors/month, unlimited users, 30 days retention
  * [sentry.io](https://sentry.io/) — Sentry tracks app exceptions in real-time, has a small free plan. Free for 5k errors per month/ 1 user, unrestricted use if self-hosted

## Search

  * [algolia.com](https://www.algolia.com/) — Hosted search-as-you-type (instant). Free hacker plan up to 10,000 documents and 100,000 operations. Bigger free plans available for community/Open Source projects
  * [bonsai.io](https://bonsai.io/) — Free 1 GB memory and 1 GB storage
  * [searchly.com](http://www.searchly.com/) — Free 2 indices and 20 MB storage
  * [pagedart.com](https://pagedart.com/) - AI search as a service the free tier includes 1000 Documents, 50000 searches. Larger free tiers are possible for worthwhile projects.

## Email

  * [10minutemail](https://10minutemail.com) - Free, temporary email for testing.
  * [AnonAddy](https://anonaddy.com) - Open-source anonymous email forwarding, create unlimited email aliases for free
  * [biz.mail.ru](https://biz.mail.ru/) — 5,000 mailboxes with 25 GB each per custom domain with DNS hosting
  * [Burnermail](https://burnermail.io/) – Free 5 Burner Email Addresses, 1 Mailbox, 7 day Mailbox History
  * [Buttondown](https://buttondown.email/) — Newsletter service. Up to 1,000 subscribers free
  * [cloudmersive.com](https://www.cloudmersive.com/email-verification-api) — Email validation and verification API for developers, 2,000 free API requests/month
  * [Contact.do](https://contact.do/) — Contact form in a link (bitly for contact forms) - totally free!
  * [debugmail.io](https://debugmail.io/) — Easy to use testing mail server for developers
  * [elasticemail.com](https://elasticemail.com) — 100 free emails/day. 1,000 emails for $0.09 through API (pay as you go).
  * [forwardemail.net](https://forwardemail.net) — Free email forwarding for custom domains. Create and forward an unlimited amount of email addresses with your domain name.
  * [ImprovMX](https://improvmx.com) – Free email forwarding
  * [inumbo.com](http://inumbo.com/) — SMTP based spam filter, free for 10 users
  * [kickbox.io](https://kickbox.io/) — Verify 100 emails free, real-time API available
  * [mail-tester.com](https://www.mail-tester.com) — Test if email's dns/spf/dkim/dmarc settings are correct, 20 free/month
  * [mailboxlayer.com](https://mailboxlayer.com/) — Email validation and verification JSON API for developers. 1,000 free API requests/month
  * [mailcatcher.me](https://mailcatcher.me/) — Catches mail and serves it through a web interface
  * [mailchimp.com](https://mailchimp.com/) — 2,000 subscribers and 12,000 emails/month free
  * [MailerLite.com](https://www.mailerlite.com) — 1,000 subscribers/month, unlimited email free
  * [mailinator.com](https://www.mailinator.com/) — Free, public, email system where you can use any inbox you want
  * [mailjet.com](https://www.mailjet.com/) — 6,000 emails/month free
  * [mailkitchen](https://www.mailkitchen.com/) — Free for life without commitment, 10,000 emails/month, 1,000 emails/day
  * [Mailnesia](https://mailnesia.com) - Free temporary/disposable email, which auto visit registration link.
  * [mailtrap.io](https://mailtrap.io/) — Fake SMTP server for development, free plan with 1 inbox, 50 messages, no team member, 2 emails/second, no forward rules
  * [migadu.com](https://www.migadu.com/) — Email Hosting (Webmail, SMTP, IMAP, ...) — free plan is limited to 10 outgoing mails/day
  * [mohmal.com](https://www.mohmal.com/en) — Disposable temporary email
  * [moosend.com](https://moosend.com/) — Mailing list management service. Free account for 6 months for startups
  * [pepipost.com](https://pepipost.com) — 30k emails free for first month, then first 100 emails/day free
  * [phplist.com](https://phplist.com/) — Hosted version allow 300 emails/month free
  * [postale.io](https://postale.io/) — Free domain email addresses for up to 5 users per domain, unlimited domains, POP3/IMAP enabled, no ads
  * [postmarkapp.com](https://postmarkapp.com/) - 100 emails/month free, unlimited DMARC weekly digests
  * [Sender](https://www.sender.net) Up to 15 000 emails/month - Up to 2 500 subscribers
  * [sendgrid.com](https://sendgrid.com/) — 100 emails/day and 2,000 contacts free
  * [sendinblue.com](https://www.sendinblue.com/) — 9,000 emails/month free
  * [sendpulse.com](https://sendpulse.com) — 50 emails free/hour, first 12,000 emails/month free
  * [socketlabs.com](https://www.socketlabs.com) - 40k emails free for first month, then first 2000 emails/month free
  * [sparkpost.com](https://www.sparkpost.com/) — First 500 emails/month free
  * [Substack](https://substack.com) — Unlimited free newsletter service. Start paying when you charge for it.
  * [testmail.app](https://testmail.app/) - Automate end-to-end email tests with unlimited mailboxes and a GraphQL API. 100 emails/month free forever, unlimited free for open source.
  * [tinyletter.com](https://tinyletter.com/) — 5,000 subscribers/month free
  * [trashmail.com](https://www.trashmail.com) - Free disposable email addresses with forwarding and automatic address expiration
  * [Validator.Pizza](https://www.validator.pizza/) — Free API to detect disposable emails
  * [Verifalia](https://verifalia.com/email-verification-api) — Real-time email verification API with mailbox confirmation and disposable email address detector; 25 free email verifications/day.
  * [verimail.io](https://verimail.io/) — Bulk and API email verification service. 100 free verifications/month
  * [Yandex.Connect](https://connect.yandex.com/pdd/) — Free email and DNS hosting for up to 1,000 users
  * [yopmail.fr](http://www.yopmail.fr/en/) — Disposable email addresses
  * [zoho.com](https://www.zoho.com/mail/) — Free Webmail and collaboration for up to 5 users
  * [SimpleLogin](https://simplelogin.io/) – Open source, self-hostable email alias/forwarding solution. Free 5 Aliases, unlimited bandwith, unlimited reply/send. Free for educational staffs (student, researcher, etc).

## Font
  * [dafont](https://www.dafont.com/) - The fonts presented on this website are their authors' property, and are either freeware, shareware, demo versions or public domain.
  * [Everything Fonts](https://everythingfonts.com/) - Offers multiple tools; @font-face, Units Converter, Font Hinter and Font Submitter.
  * [Font Squirrel](https://www.fontsquirrel.com/) - Freeware fonts that is licensed for commercial work. Hand-selected these typefaces and presenting them in an easy-to-use format.
  * [Google Fonts](https://fonts.google.com/) - Lots of free fonts that are easy and quick to install in a website via a download or a link to Google's CDN.
  * [FontGet](https://www.fontget.com/) - Has a variety of fonts available to download and sorted neatly with tags.

## Forms

  * [99inbound.com](https://www.99inbound.com/) - Build forms and share them online. Get an email or Slack message for each submission. Free plan has 2 forms, 100 entries per month, basic email & Slack.
  * [Formcake.com](https://formcake.com) - Form backend for devs, free plan allows unlimited forms, 100 submissions, Zapier integration. No libraries or dependencies required.
  * [Formcarry.com](https://formcarry.com) - HTTP POST Form endpoint, Free plan allows 100 submissions per month.
  * [formingo.co](https://www.formingo.co/)- Easy HTML forms for static websites, get started for free without registering an account. Free plan allows 500 submissions per month, customizable reply-to email address.
  * [formlets.com](https://formlets.com/) — Online forms, unlimited single page forms/month, 100 submissions/month, email notifications.
  * [formspark.io](https://formspark.io/) -  Form to Email service, free plan allows unlimited forms, 500 submissions per month, support by Customer assistance team.
  * [Formspree.io](https://formspree.io/) — Send email using an HTTP POST request. Free tier limits to 1000 submissions per month and must expose email address in the API call.
  * [getform.io](https://getform.io/) - Form backend platform for designers and developers, 1 form, 100 submissions, Single file upload, 100MB file storage.
  * [Kwes.io](https://kwes.io/) - Feature rich form endpoint. Works great with static sites. Free plan includes up 1 website with up to 50 submissions per month.
  * [smartforms.dev](https://smartforms.dev/) - Powerful and easy form backend for your website, forever free plan allows 50 submissions per month, 100MB file storage, Zapier integration, CSV/JSON export, custom redirect, custom response page, Telegram & Slack bot, single email notifications.
  * [staticforms.xyz](https://www.staticforms.xyz/) - Integrate HTML forms easily without any server side code for free. After user submits the form an email will be sent to your registered address with form content.
  * [Typeform.com](https://www.typeform.com/) — Include beautifully designed forms on websites.  Free plan allows only 10 fields per form and 100 responses per month.
  * [WaiverStevie.com](https://waiverstevie.com) - Electronic Signature platform with a REST API. Receive notifications with webhooks. Free plan watermarks signed documents, but allows unlimited envelopes + signatures.
  * [Wufoo](https://www.wufoo.com/) - Quick forms to use on websites. Free plan has a limit of 100 submissions each month.

## CDN and Protection

  * [bootstrapcdn.com](https://www.bootstrapcdn.com/) — CDN for bootstrap, bootswatch and fontawesome.io
  * [cdnjs.com](https://cdnjs.com/) — CDN for JavaScript libraries, CSS libraries, SWF, images, etc.
  * [cloudflare.com](https://www.cloudflare.com/) — Basic service is free, good for a blog, it also offers a free SSL certificate service and 5 firewall rules.
  * [ddos-guard.net](https://ddos-guard.net/store/web) — Free CDN, DDoS protection and SSL certificate
  * [developers.google.com](https://developers.google.com/speed/libraries/) — The Google Hosted Libraries is a content distribution network for the most popular, Open Source JavaScript libraries
  * [jare.io](http://www.jare.io) — CDN for images. Uses AWS CloudFront
  * [jsdelivr.com](https://www.jsdelivr.com/) — CDN of OSS (JS, CSS, fonts) for developers and webmasters, accepts PRs to add more
  * [Microsoft Ajax](https://docs.microsoft.com/en-us/aspnet/ajax/cdn/overview) — The Microsoft Ajax CDN hosts popular third-party JavaScript libraries such as jQuery and enables you to easily add them to your Web application
  * [netdepot.com](https://www.netdepot.com/cdn/) — First 100 GB free/month
  * [ovh.ie](https://www.ovh.ie/ssl-gateway/) — Free DDoS protection and SSL certificate
  * [PageCDN.com](https://pagecdn.com/) - Offers free Public CDN for everyone, and free Private CDN for opensource / nonprofits.
  * [pika.dev/cdn](https://www.pika.dev/cdn) — The 100% Native ES Module JavaScript CDN
  * [raw.githack.com](https://raw.githack.com/) — A modern replacement of **rawgit.com** which simply hosts file using Cloudflare
  * [section.io](https://www.section.io/) — A simple way to spin up and manage a complete Varnish Cache solution. Supposedly free forever for one site
  * [speeder.io](https://speeder.io/) — Uses KeyCDN. Automatic image optimization and free CDN boost. Free and does not require any server changes
  * [staticaly.com](https://staticaly.com/) — CDN for Git repos (GitHub, GitLab, Bitbucket), WordPress-related assets and images
  * [toranproxy.com](https://toranproxy.com/) — Proxy for Packagist and GitHub. Never fail CD. Free for personal use, 1 developer, no support
  * [unpkg.com](https://unpkg.com/) — CDN for everything on npm
  * [Web Support Revolution](https://w.tools/) — Free CDN, backup, firewall, antivirus and monitoring.
  * [Namecheap Supersonic](https://www.namecheap.com/supersonic-cdn/#free-plan) — Free DDoS protection

## PaaS

  * [anvil.works](https://anvil.works) - Web app development with nothing but Python. Free tier with unlimited apps.
  * [appharbor.com](https://appharbor.com/) — A .Net PaaS that provides 1 free worker
  * [configure.it](https://www.configure.it/) — Mobile app development platform, free for 2 projects, limited features but no resource limits
  * [codenameone.com](https://www.codenameone.com/) — Open source, cross platform, mobile app development toolchain for Java/Kotlin developers. Free for commercial use with unlimited number of projects
  * [dronahq.com](https://www.dronahq.com/) — No code application development platform for enterprises to visually develop application, integrate with existing systems to Build internal apps, processes and forms, rapidly. Free plan offers 200 Tasks/month, Unlimited Draft Apps and 1 Published Apps
  * [engineyard.com](https://www.engineyard.com/) — Engine Yard provides 500 free hours
  * [firebase.google.com](https://firebase.google.com) — Build real-time apps, the free plan has 100 max connections, 10 GB data transfer, 1 GB data storage, 1 GB hosting storage and 10 GB hosting transfer
  * [gearhost.com](https://www.gearhost.com/pricing) — Platform for .NET and PHP apps. 256 MB of RAM for free on a shared server with limited resources
  * [gigalixir.com](https://gigalixir.com/) - Gigalixir provide 1 free instance that never sleeps, and free-tier PostgreSQL database limited to 2 connections, 10, 000 rows and no backups, for Elixir/Phoenix apps.
  * [glitch.com](https://glitch.com/) — Free unlimited public/private hosting with features such as code sharing and real-time collaboration
  * [heroku.com](https://www.heroku.com/) — Host your apps in the cloud, free for single process apps
  * [dplyr.dev](https://www.dplyr.dev) - Deploy Web Apps with Databases. Free for deploying on your machines. Maximum 2 deployments
  * [KintoHub](https://www.kintohub.com/) — KintoHub is an all-in-one platform to combine and deploy your backend services, websites, cron jobs, databases and everything your app needs in one place.
  * [Krucible](https://usekrucible.com) — Krucible is a platform for creating Kubernetes clusters for testing and development. Free tier accounts come with 25 cluster-hours per month.
  * [kubesail.com](https://kubesail.com) - Managed Kubernetes namespace service designed for developers. Free developer accounts come with with 1 Core of CPU, 512MB of RAM, 100MB of storage and 1 domain.
  * [K8Spin](https://k8spin.cloud) - Managed Kubernetes namespace service designed for developers. Free developer accounts come with with 100 mCore of CPU, 128MB of RAM.
  * [ZARVIS](https://zarvis.ai) - Free managed Kubernetes namespace for open source Github project. Free 1GB memory and 1 vCPU.
  * [mendix.com](https://www.mendix.com/) — Rapid Application Development for Enterprises, unlimited number of free sandbox environments supporting 10 users, 100 MB of files and 100 MB database storage each
  * [Okteto Cloud](https://okteto.com) - Managed Kubernetes service designed for developers. Free developer accounts come with 8GB of RAM, 4 CPUs and 5GB Disk space. The apps sleep after 24 hours of inactivity.
  * [outsystems.com](https://www.outsystems.com/) — Enterprise web development PaaS for on-premise or cloud, free "personal environment" offering allows for unlimited code and up to 1 GB database
  * [pipedream.com](https://pipedream.com) - An integration platform built for developers. Develop any workflow, based on any trigger. Workflows are code, which you can run [for free](https://docs.pipedream.com/pricing/). No server or cloud resources to manage.
  * [pythonanywhere.com](https://www.pythonanywhere.com/) — Cloud Python app hosting. Beginner account is free, 1 Python web application at your-username.pythonanywhere.com domain, 512 MB private file storage, one MySQL database
  * [sandstorm.io](https://sandstorm.io/) — Sandstorm is an open source operating system for personal and private clouds. Free plan offers 200 MB storage and 5 grains free
  * [scn.sap.com](https://scn.sap.com/docs/DOC-56411) — The in-memory Platform-as-a-Service offering from SAP. Free developer accounts come with 1 GB structured, 1 GB unstructured, 1 GB of Git data and allow you to run HTML5, Java and HANA XS apps
  * [staroid.com](https://staroid.com) - Managed Kubernetes namespace service designed to fund open source developers. Free 8 CPUs and 16GB of RAM namespace to test branches and pull requests of public repository. Free test namespace shutdown every 30 minutes. Maximum 2 concurrent test namespaces.
  * [workers.dev](https://workers.dev) - Deploy serverless code for free on Cloudflare's global network. 100,000 free requests per day with a workers.dev subdomain.
  * [vercel.com](https://vercel.com/) — Serverless platform with support for multiple languages (including static sites) and single command deployment. Free tier includes SSL, unlimited (Fair Use) bandwidth, 100 deployments.
  * [Platform9](https://platform9.com/) - Managed Kubernetes service designed for developers. Free developer accounts come with up to 3 clusters & 20 nodes cluster.
  * [fly.io](https://fly.io/) - Fly is a platform for applications that need to run globally. It runs your code close to users and scales compute in cities where your app is busiest. Write your code, package it into a Docker image, deploy it to Fly's platform and let that do all the work to keep your app snappy. Free for side projects, $10/mo of service credit that automatically applies to any paid service. And if you ran really small virtual machines, credits will go a long way.

## BaaS

  * [ably.com](https://www.ably.com) - APIs for realtime messaging, push notifications, and event-driven API creation. Free plan has 3m messages/mo, 100 concurrent connections, 100 concurrent channels.
  * [back4app.com](https://www.back4app.com) - Back4App is an easy-to-use, flexible and scalable backend based on Parse Platform.
  * [backendless.com](https://backendless.com/) — Mobile and Web Baas, with 1 GB file storage free, push notifications 50000/month, and 1000 data objects in table.
  * [blockspring.com](https://www.blockspring.com/) — Cloud functions. Free for 5 million runs/month
  * [getstream.io](https://getstream.io/) — Build scalable news feeds and activity streams in a few hours instead of weeks, free for 3 million feed updates/month
  * [hasura.io](https://hasura.io/) — Platform to build and deploy app backends fast, free for single node cluster.
  * [iron.io](https://www.iron.io/) — Async task processing (like AWS Lambda) with free tier and 1-month free trial
  * [netlicensing.io](https://netlicensing.io) - A cost-effective and integrated Licensing-as-a-Service (LaaS) solution for your software on any platform from Desktop to IoT and SaaS. Basic Plan for *FREE* while you are a student.
  * [onesignal.com](https://onesignal.com/) — Unlimited free push notifications
  * [paraio.com](https://paraio.com) — Backend service API with flexible authentication, full-text search and caching. Free for 1 app, 1GB app data.
  * [posthook.io](https://posthook.io/) — Job Scheduling Service. Allows you to schedule requests for specific times. 500 scheduled requests/month free.
  * [progress.com](https://www.progress.com/kinvey) — Mobile backend, starter plan has unlimited requests/second, with 1 GB of data storage. Enterprise application support
  * [pubnub.com](https://www.pubnub.com/) — Free push notifications for up to 1 million messages/month and 100 active daily devices
  * [pushbots.com](https://pushbots.com/) — Push notification service. Free for up to 1.5 million pushes/month
  * [pushcrew.com](https://pushcrew.com/) — Push notification service. Unlimited notifications up to 2000 Subscribers
  * [pusher.com](https://pusher.com/beams) — Free, unlimited push notifications for 2000 monthly active users. A single API for iOS and Android devices.
  * [pushtechnology.com](https://www.pushtechnology.com/) — Real-time Messaging for browsers, smartphones and everyone. 100 concurrent connections. Free 10 GB data/month
  * [quickblox.com](https://quickblox.com/) — A communication backend for instant messaging, video and voice calling and push notifications
  * [simperium.com](https://simperium.com/) — Move data everywhere instantly and automatically, multi-platform, unlimited sending and storage of structured data, max. 2,500 users/month
  * [stackstorm.com](https://stackstorm.com/) — Event-driven automation for apps, services and workflows, free without flow, access control, LDAP,...
  * [streamdata.io](https://streamdata.io/) — Turns any REST API into an event-driven streaming API. Free plan up to 1 million messages and 10 concurrent connections
  * [tyk.io](https://tyk.io/) — API management with authentication, quotas, monitoring and analytics. Free cloud offering
  * [zapier.com](https://zapier.com/) — Connect the apps you use, to automate tasks. 5 zaps, every 15 minutes and 100 tasks/month
  * [LeanCloud](https://leancloud.app/) — Mobile backend. 1GB of data storage, 256MB instance, 3K API requests/day, 10K pushes/day are free. (API is very similar to Parse Platform)

## Web Hosting

  * [000WebHost](https://www.000webhost.com/) — Zero cost website hosting with PHP, MySQL, cPanel & no ads!
  * [Amezmo](https://www.amezmo.com) — PHP hosting with MySQL for developers. Docker container based. Modern PHP 7, Automatic Deployments with Git, free SSL for custom domains.
  * [Alwaysdata](https://www.alwaysdata.com/) — 100 MB free web hosting with support for MySQL, PostgreSQL, CouchDB, MongoDB, PHP, Python, Ruby, Node.js, Elixir, Java, Deno, custom web servers, access via FTP, WebDAV and SSH; mailbox, mailing list and app installer included.
  * [Awardspace.com](https://www.awardspace.com) — Free web hosting + a free short domain, PHP, MySQL, App Installer, Email Sending & No Ads.
  * [Bubble](https://bubble.io/) — Visual programming to build web and mobile apps without code, free with Bubble branding.
  * [Byet](https://byet.host) — Byet provides you with a massive free, and ad-free load balanced free web hosting service including PHP, MySQL, FTP, Vistapanel & more!..
  * [cloudno.de](https://cloudno.de/) — Free cloud hosting for Node.js apps.
  * [devport.co](http://devport.co/) — Turn GitHub projects, apps and websites into a personal developer portfolio
  * [Endless Hosting](https://theendlessweb.com/) — 300 MB storage, Free SSL, PHP, MySQL, FTP, free sub-domains, E-Mail, DNS, beatiful panel UI. One of the best! 
  * [Fenix Web Server](https://preview.fenixwebserver.com) - A developer desktop app for hosting sites locally and sharing them publically (in realtime). Work however you like, using its beautiful user interface, API, and/or CLI.
  * [Free Hosting](http://freehostingnoads.net/) — Free Hosting With PHP 5, Perl, CGI, MySQL, FTP, File Manager, POP E-Mail, free sub-domains, free domain hosting, DNS Zone Editor, Web Site Statistics, FREE Online Support and many more features not offered by other free hosts.
  * [Freehostia](https://www.freehostia.com) — FreeHostia offers free hosting services incl. an industry-best Control Panel & a 1-click installation of 50+ free apps. Instant setup. No forced ads.
  * [gitlab.com](https://about.gitlab.com/product/pages/) — Hosting static site directly from GitLab repository
  * [heliohost.org](https://www.heliohost.org) — Community powered free hosting for everyone.
  * [InfinityFree](https://infinityfree.net/) - Free PHP website hosting with MySQL, cPanel, and no ads.
  * [neocities.org](https://neocities.org) — Static, 1 GB free storage with 200 GB Bandwidth.
  * [netlify.com](https://www.netlify.com/) — Builds, deploy and hosts static site or app, free for 100 GB data and 100 GB/month bandwidth
  * [commons.host](https://commons.host/) - Static web hosting and CDN.100% free and open source software (FOSS). With a commercially sustainable software as a service (SaaS) to fund R&D.
  * [pages.github.com](https://pages.github.com/) — Hosting static site directly from GitHub repository
  * [pantheon.io](https://pantheon.io/) — Drupal and WordPress hosting, automated DevOps and scalable infrastructure. Free for developers and agencies
  * [pony.icu](https://pony.icu/) — Free Web Hosting with Unlimited Disk Space, Unlimited Bandwidth and Unlimited Websites from PonyICU. PHP and MySQL included.
  * [raidboxes.io](https://raidboxes.io/) — Managed WordPress hosting with lots of included features. Free for developers and agencies, comes with custom domain support.
  * [readthedocs.org](https://readthedocs.org/) — Free documentation hosting with versioning, PDF generation and more
  * [render.com](https://render.com) — A unified platform to build and run all your apps and web app free SSL, a global CDN, private networks and auto deploys from Git, free for static web page.
  * [sourceforge.net](https://sourceforge.net/) — Find, Create and Publish Open Source software for free
  * [surge.sh](https://surge.sh/) — Static web publishing for Front-End developers. Unlimited sites with custom domain support
  * [tilda.cc](https://tilda.cc/) — One site, 50 pages, 50 MB storage, only the main pre-defined blocks among 170+ available, no fonts, no favicon and no custom domain
  * [txti.es](https://txti.es/) — Quickly create web pages with markdown.
  * [Versoly](https://versoly.com/) — SaaS focussed website builder - unlimited websites, 70+ blocks, 5 templates, custom CSS, favicon, SEO and forms. No custom domain.
  * [HostingTocDo](https://hostingtocdo.cyou/) — Free Unlimited Web Hosting Service for PHP, MySQL no ads include.

## DNS

  * [1984.is](https://www.1984.is/product/freedns/) — Free DNS service with API, and lots of other free DNS features included.
  * [biz.mail.ru](https://biz.mail.ru) — Free email and DNS hosting for up to 5,000 users
  * [Cloudflare](https://www.cloudflare.com/) - Free DNS.  Unlimited number of domains.
  * [cloudns.net](https://www.cloudns.net/) — Free DNS hosting up to 1 domain with 50 records
  * [dns.he.net](https://dns.he.net/) — Free DNS hosting service with Dynamic DNS Support
  * [dnspod.com](https://www.dnspod.com/) — Free DNS hosting.
  * [duckdns.org](https://www.duckdns.org/) — Free DDNS with up to 5 domains on the free tier. With configuration guides for various setups.
  * [dynu.com](https://www.dynu.com/) — Free dynamic DNS service
  * [fosshost.org](https://fosshost.org/) - Free open source hosting VPS, web, storage and mirror hosting 
  * [freedns.afraid.org](https://freedns.afraid.org/) — Free DNS hosting
  * [freenom.com](https://freenom.com/) — Free domain provider. Get FQDN for free.
  * [luadns.com](https://www.luadns.com/) — Free DNS hosting, 3 domains, all features with reasonable limits
  * [namecheap.com](https://www.namecheap.com/domains/freedns/) — Free DNS. No limit on number of domains
  * [noip](https://www.noip.com/) — a dynamic dns service that allows up to 3 hostnames free with confirmation every 30 days
  * [ns1.com](https://ns1.com/) — Data Driven DNS, automatic traffic management, 500k free queries
  * [pointhq.com](https://pointhq.com/developer) — Free DNS hosting on Heroku.
  * [selectel.com](https://selectel.com/services/dns/) — Free DNS hosting, anycast
  * [web.gratisdns.dk](https://web.gratisdns.dk/domaener/dns/) — Free DNS hosting.
  * [Yandex.Connect](https://connect.yandex.com/pdd/) — Free email and DNS hosting for up to 1,000 users
  * [zilore.com](https://zilore.com/en/dns) — Free DNS hosting.
  * [zoneedit.com](https://www.zoneedit.com/free-dns/) — Free DNS hosting with Dynamic DNS Support.
  * [zonewatcher.com](https://zonewatcher.com) — Automatic backups and DNS change monitoring. 1 domain free
  * [huaweicloud.com](https://www.huaweicloud.com/intl/en-us/product/dns.html) – Free DNS hosting by Huawei

## IaaS

  * [backblaze.com](https://www.backblaze.com/b2/) — Backblaze B2 cloud storage. Free 10 GB (Amazon S3-like) object storage for unlimited time
  * [scaleway.com](https://www.scaleway.com/en/object-storage/) — S3-Compatible Object Storage. Free 75 GB storage and external outgoing traffic
  * [terraform.io](https://www.terraform.io/) — Terraform Cloud. Free remote state management and team collaboration for teams up to 5 users.

## DBaaS

   * [airtable.com](https://airtable.com/) — Looks like a spreadsheet, but it's a relational database, unlimited bases, 1,200 rows/base and 1,000 API requests/month
   * [Astra](https://astra.datastax.com/register) — Cloud Native Cassandra as a Service with 10GB free tier
   * [elephantsql.com](https://www.elephantsql.com/) — PostgreSQL as a service, 20 MB free
   * [cloudamqp.com](https://www.cloudamqp.com/) — RabbitMQ as a Service, up to 1M messages/month and 20 connections free
   * [FaunaDB](https://fauna.com/) — Serverless cloud database, with native GraphQL, multi-model access and daily free tiers up to 5GB
   * [graphenedb.com](https://www.graphenedb.com/) — Neo4j as a service, up to 1,000 nodes and 10,000 relations free
   * [heroku.com](https://www.heroku.com/) — PostgreSQL as a service, up to 10,000 rows and 20 connections free (provided as an "addon," but can be attached to an otherwise empty app and accessed externally)
   * [MongoDB Atlas](https://www.mongodb.com/cloud/atlas) — free tier gives 512 MB
   * [redsmin.com](https://www.redsmin.com/) — Online real-time monitoring and administration service for Redis, 1 Redis instance free
   * [MemCachier](https://www.memcachier.com/) — Managed Memcache service. Free for up to 25MB, 1 Proxy Server and basic analytics
   * [scalingo.com](https://scalingo.com/) — Primarily a PaaS but offers a 128MB to 192MB free tier of MySQL, PostgreSQL or MongoDB
   * [skyvia.com](https://skyvia.com/) — Cloud Data Platform, offers free tier and all plans are completely free while in beta
   * [remotemysql.com](https://remotemysql.com) — Remote MySQL Database hosting, setup is instant and use phpMyAdmin for administration, free for 100Mb data, free backups, no query limits and 99% uptime.
   * [InfluxDB](https://www.influxdata.com/) — Timeseries database, free up to 3MB/5 minutes writes, 30MB/5 minutes reads and 10,000 cardinalities series
   * [Quickmetrics](https://www.quickmetrics.io/) — Timeseries database with dashboard included, free up to 10,000 events/day and total of 5 metrics.
   * [restdb.io](https://restdb.io/) - a fast and simple NoSQL cloud database service. With restdb.io you get schema, relations, automatic REST API (with MongoDB-like queries) and an efficient multi-user admin UI for working with data. Free plan allows 3 users, 2500 records and 1 API requests per second.
   * [Unbounded](https://www.unbounded.cloud/) - a NoSQL DBaaS which uses Javascript as a query language. Free tier allows 50,000 reads and writes per month, forever.

## STUN, WebRTC, Web Socket Servers and Other Routers

   * [conveyor.cloud](https://conveyor.cloud/) — Visual Studio extension to expose IIS Express to the local network or over a tunnel to a public URL.
   * [Hamachi](https://www.vpn.net/) — LogMeIn Hamachi is a hosted VPN service that lets you securely extend LAN-like networks to distributed teams with free plan allows unlimited networks with up to 5 peoples
   * [Radmin VPN](https://www.radmin-vpn.com/) - Connect multiple computers together via a VPN enabling LAN-like networks. Unlimited peers. (Hamachi alternative)
   * [localhost.run](https://localhost.run/) — Instantly share your localhost environment! No download required. Run your app on port 8080 and then run this command and share the URL.
   * [ngrok.com](https://ngrok.com/) — Expose locally running servers over a tunnel to a public URL.
   * [segment.com](https://segment.com/) — Hub to translate and route events to other third-party services. 100,000 events/month free
   * [serveo.net](https://serveo.net/) — Quickly expose any local port to the public internet on a servo subdomain using an SSH tunnel, includes SSH GUI to replay requests over HTTP.
   * [stun:global.stun.twilio.com:3478?transport=udp](stun:global.stun.twilio.com:3478?transport=udp) — Twilio STUN
   * [stun:stun.l.google.com:19302](stun:stun.l.google.com:19302) — Google STUN
   * [webhookrelay.com](https://webhookrelay.com) — Manage, debug, fan-out and proxy all your webhooks to public or internal (ie: localhost) destinations. Also, expose servers running in a private network over a tunnel by getting a public HTTP endpoint (`https://yoursubdomain.webrelay.io <----> http://localhost:8080`).
   * [ZeroTier](https://www.zerotier.com) — FOSS managed virtual Ethernet as a service. Unlimited end-to-end encrypted networks of 100 clients on free plan. Clients for desktop/mobile/NA; web interface for configuration of custom routing rules and approval of new client nodes on private networks.

## Issue Tracking and Project Management

   * [acunote.com](https://www.acunote.com/) — Free project management and SCRUM software for up to 5 team members
   * [asana.com](https://asana.com/) — Free for private project with collaborators
   * [Azure DevOps](https://azure.microsoft.com/services/devops/) — Unlimited free private code repositories; Tracks bugs, work items, feedback and more
   * [Basecamp](https://basecamp.com/personal) - To-do lists, milestone management, forum-like messaging, file sharing, and time tracking. Up to 3 projects, 20 users, and 1GB of storage space.
   * [bitrix24.com](https://www.bitrix24.com/) — Free intranet and project management tool
   * [cacoo.com](https://cacoo.com/) — Online diagrams in real-time: flowchart, UML, network. Free max. 15 users/diagram, 25 sheets
   * [clickup.com](https://clickup.com/) — Project management. Free, premium version with cloud storage. Mobile applications and Git integrations available
   * [Cloudcraft](https://cloudcraft.co/) — Design a professional architecture diagram in minutes with the Cloudcraft visual designer, optimized for AWS with smart components that show live data too.
   * [Clubhouse](https://clubhouse.io/) - Project management platform. Free for up to 10 users forever
   * [Confluence](https://www.atlassian.com/software/confluence) - Atlassian's content collaboration tool used to help teams collaborate and share knowledge efficiently. Free plan up to 10 users.
   * [contriber.com](https://www.contriber.com/) — Customizable project management platform, free starter plan, 5 workspaces
   * [draw.io](https://www.draw.io/) — Online diagrams stored locally, in Google Drive, OneDrive or Dropbox. Free for all features and storage levels
   * [funretro.io](https://www.funretro.io/) — Free simple and intuitive sprint retrospective tool
   * [github.com](https://github.com/) — In addition to its Git storage facility, GitHub offers basic issue tracking
   * [Gitlab](https://gitlab.com) - Offers basic issue tracking for projects.
   * [gleek.io](https://www.gleek.io) — Free description-to-diagrams tool for developers. Create informal, UML class, object, or entity-relationship diagrams using your keyword.
   * [gliffy.com](https://www.gliffy.com/) — Online diagrams: flowchart, UML, wireframe,... Also plugins for Jira and Confluence. 5 diagrams and 2 MB free
   * [GraphQL Inspector](https://github.com/marketplace/graphql-inspector) - GraphQL Inspector ouputs a list of changes between two GraphQL schemas. Every change is precisely explained and marked as breaking, non-breaking or dangerous.
   * [huboard.com](https://huboard.com/) — Instant project management for your GitHub issues, free for Open Source
   * [Instabug](https://instabug.com) —  A comprehensive bug reporting and in-app feedback SDK for mobile apps. Free plan up to 1 app and 1 member.
   * [Ilograph](https://www.ilograph.com/)  — interactive diagrams that allow users to see their infrastructure from multiple perspectives and levels of detail. Diagrams can be expressed in code. Free tier has unlimited private diagrams with up to 3 viewers.
   * [Jira](https://www.atlassian.com/software/jira) — Advanced software development project management tool used in many corporate environments. Free plan up to 10 users.
   * [kanbanflow.com](https://kanbanflow.com/) — Board-based project management. Free, premium version with more options
   * [kanbantool.com](https://kanbantool.com/) — Kanban board-based project management. Free, paid plans with more options
   * [kanrails.com](https://kanrails.com/) — Kanban board-based project management. Free for 3 collaborators, 2 projects and 5 tracks. Paid plans available for unlimited collaborators, projects and tracks.
   * [Kumu.io](https://kumu.io/)  — Relationship maps with animation, decorations, filters, clustering, spreadsheet imports and more. Free tier allows unlimited public projects. Graph size unlimited. Free private projects for students. Sandbox mode is available if you prefer to not leave your file publicly online (upload, edit, download, discard).
   * [LeanBoard](https://www.leanboard.io) — Collaborative whiteboard with sticky notes for your GitHub issues (Useful for Example Mapping and other techniques)
   * [MeuScrum](https://www.meuscrum.com/en) - Free online scrum tool with kanban board
   * [Office 365 Developer](https://developer.microsoft.com/en-us/office/dev-program) — Free one-year Office 365 E3 subscription for development/testing.
   * [Ora](https://ora.pm/) - Agile task management & team collaboration. Free for up to 3 users and files are limited to 10 MB.
   * [pivotaltracker.com](https://www.pivotaltracker.com/) — Free for unlimited public projects and two private projects with 3 total active users (read-write) and unlimited passive users (read-only).
   * [plan.io](https://plan.io/) — Project Management with Repository Hosting and more options. Free for 2 users with 10 customers and 500MB Storage
   * [planitpoker.com](https://www.planitpoker.com/) — Free online planning poker (estimation tool)
   * [senseitool.com](https://www.senseitool.com/) — An agile retrospective tool - Free.
   * [SpeedBoard](https://speedboard.app) - Board for Agile and Scrum retrospectives - Free.
   * [Tadum](https://tadum.app) - Meeting agenda and minutes app designed for recurring meetings, free for teams up to 10
   * [taiga.io](https://taiga.io/) — Project management platform for startups and agile developers, free for Open Source
   * [targetprocess.com](https://www.targetprocess.com/) — Visual project management, from Kanban and Scrum to almost any operational process. Free for unlimited users, up to 1,000 data entities {[more details](https://www.targetprocess.com/pricing/)}
   * [taskade.com](https://www.taskade.com/) — Real-time collaborative task lists and outlines for teams
   * [taskulu.com](https://taskulu.com/) — Role based project management. Free up to 5 users. Integration with GitHub/Trello/Dropbox/Google Drive
   * [testlio.com](https://testlio.com/) — Issue tracking, test management and beta testing platform. Free for private use
   * [terrastruct.com](https://terrastruct.com/) — Online diagram maker specifically for software architecture. Free tier up to 4 layers per diagram.
   * [todoist.com](https://todoist.com/) — Collaborative and individual task management. Free, Premium and Team plans are available. Discounts provided for eligible users.
   * [trello.com](https://trello.com/) — Board-based project management. Unlimited Personal Boards, 10 Team Boards.
   * [ubertesters.com](https://ubertesters.com/) — Test platform, integration and crowdtesters, 2 projects, 5 members
   * [vivifyscrum.com](https://www.vivifyscrum.com/) — Free tool for Agile project management. Scrum Compatible
   * [YouTrack](https://www.jetbrains.com/youtrack/buy/#edition=incloud) — Free hosted YouTrack (InCloud) for FOSS projects, private projects (free for 3 users). Includes time tracking and agile boards
   * [zenhub.io](https://www.zenhub.io/) — The only project management solution inside GitHub. Free for public repos, OSS and nonprofit organizations
   * [zepel.io](https://zepel.io/) - The project management tool that lets you plan features, collaborate across disciplines, and build software together. Free up to 5 members. No feature restrictions.
   * [zenkit.com](https://zenkit.com) — Project management and collaboration tool. Free for up to 5 members, 5 GB attachments.

## Storage and Media Processing
   * [sirv.com](https://sirv.com/) — Smart Image CDN with on-the-fly image optimization and resizing. Free tier includes 500 MB of storage and 2 GB bandwidth.
   * [image4.io](https://image4.io/) — Image upload, powerful manipulations, storage and delivery for websites and apps, with SDK's, integrations and migration tools. Free tier includes 25 credits. 1 credit is equal to 1 GB of CDN usage, 1GB of storage or 1000 image transformations.
   * [cloudimage.com](https://cloudimage.com/) — Full image optimization and CDN service with 1500+ Points of Presence around the world. A variety of image resizing, compression, watermarking functions. Open source plugins for responsive images, 360 image making and image editing. Free monthly plan with 25GB of CDN traffic and 25GB of cache storage and unlimited transformations.
   * [cloudinary.com](https://cloudinary.com/) — Image upload, powerful manipulations, storage and delivery for sites and apps, with libraries for Ruby, Python, Java, PHP, Objective-C and more. Perpetual free tier includes 7,500 images/month, 2 GB storage, 5 GB bandwidth
   * [easyDB.io](https://easydb.io/) — one-click, hosted database provider. They provide a database for the programming language of your choice for development purposes. The DB is ephemeral and will be deleted after 24 or 72 hours on the free tier.
   * [embed.ly](https://embed.ly/) — Provides APIs for embedding media in a webpage, responsive image scaling, extracting elements from a webpage. Free for up to 5,000 URLs/month at 15 requests/second
   * [filestack.com](https://www.filestack.com/) — File picker, transform and deliver, free for 250 files, 500 transformations and 3 GB bandwidth
   * [gumlet.com](https://www.gumlet.com/) — Image resize-as-a-service. It also optimizes images and performs delivery via CDN. Free tier includes 1 GB bandwidth and unlimited number of image processing every month for 1 year.
   * [image-charts.com](https://www.image-charts.com/) — Unlimited image chart generation with a watermark
   * [jsonbin.io](https://jsonbin.io/) — Free JSON data storage service, ideal for small-scale web apps, website, mobile apps.
   * [kraken.io](https://kraken.io/) — Image optimization for website performance as a service, free plan up to 1 MB file size
   * [npoint.io](https://www.npoint.io/) — JSON store with collaborative schema editing
   * [otixo.com](https://www.otixo.com/) — Encrypt, share, copy and move all your cloud storage files from one place. Basic plan provides unlimited files transfer with 250 MB max. file size and allows 5 encrypted files
   * [packagecloud.io](https://packagecloud.io/) — Hosted Package Repositories for YUM, APT, RubyGem and PyPI.  Limited free plans, open source plans available via request
   * [piio.co](https://piio.co/) — Responsive image optimization and delivery for every website. Free plan for developers and personal websites. Includes free CDN, WebP and Lazy Loading out of the box.
   * [placeholder.com](https://placeholder.com/) — A quick and simple image placeholder service
   * [placekitten.com](https://placekitten.com/) — A quick and simple service for getting pictures of kittens for use as placeholders
   * [plot.ly](https://plot.ly/) — Graph and share your data. Free tier includes unlimited public files and 10 private files
   * [podio.com](https://podio.com/) — You can use Podio with a team of up to five people and try out the features of the Basic Plan, except user management
   * [QuickChart](https://quickchart.io) — Generate embeddable image charts, graphs, and QR codes
   * [redbooth.com](https://redbooth.com) — P2P file syncing, free for up to 2 users
   * [shrinkray.io](https://shrinkray.io/) — Free image optimization of GitHub repos
   * [tinypng.com](https://tinypng.com/) — API to compress and resize PNG and JPEG images, offers 500 compressions for free each month
   * [transloadit.com](https://transloadit.com/) — Handles file uploads and encoding of video, audio, images, documents. Free for Open source, charities, and students via the GitHub Student Developer Pack. Commercial applications get 2 GB free for test driving
   * [Uploadcare Developer Hub](https://uploadcare.com/hub/developers/) — Uploadcare provides media pipeline  with ultimate toolkit based on cutting-edge algorithms. All features are available for developers absolutely for free: File Uploading API and UI, Image CDN and Origin Services, Adaptive Delivery and Smart Compression.

## Design and UI

  * [Adobe XD](https://www.adobe.com/products/xd.html) - Wireframe & Prototyping tool similar to Sketch. Free plan covers: 1 active shared design spec, Adobe Fonts Free (limited set of fonts), 2GB of cloud storage.
  * [Mockplus iDoc](https://www.mockplus.com/idoc) - Mockplus iDoc is a powerful design collaboration & handoff tool. Free Plan includes 3 users and 5 projects with all features available.
  * [AllTheFreeStock](https://allthefreestock.com) - a curated list of free stock images, audio and videos.
  * [clevebrush.com](https://www.cleverbrush.com/) — Free Graphics Design / Photo Collage App, also they offer paid integration of it as component.
  * [cloudconvert.com](https://cloudconvert.com/) — Convert anything to anything. 208 supported formats including videos to gif.
  * [CodeMyUI](https://codemyui.com) - Handpicked collection of Web Design & UI Inspiration with Code Snippets.
  * [designer.io](https://www.designer.io/) — Design tool for UI, illustrations and more. Has a native app. Free.
  * [figma.com](https://www.figma.com) — Online, collaborative design tool for teams; free tier includes unlimited files and viewers with a max of 2 editors and 3 projects.
  * [imagebin.ca](https://imagebin.ca/) — Pastebin for images.
  * [Invision App](https://www.invisionapp.com) - UI design and prototyping tool. Desktop and webapp available. Free to use with 1 active prototype.
  * [landen.co](https://www.landen.co) — Generate, edit and publish beautiful websites and landing pages for your startup. All without code. Free tier allows you to have one website, fully customizable and published on the web.
  * [lensdump.com](https://lensdump.com/) - Free cloud image hosting.
  * [marvelapp.com](https://marvelapp.com/) — Design, prototyping and collaboration, free plan limited to one user and one project.
  * [Mindmup.com](https://www.mindmup.com/) — Unlimited mind maps for free, and store them in the cloud. Your mind maps are available everywhere, instantly, from any device.
  * [Octopus.do](https://octopus.do) — Visual sitemap builder. Build your website structure in real-time and rapidly share it to collaborate with your team or clients.
  * [Pencil](https://github.com/evolus/pencil) - Open source design tool using Electron.
  * [pexels.com](https://www.pexels.com/) - Free stock photos for commercial use. Has free API that allows you to search photos by keywords.
  * [photopea.com](https://www.photopea.com) — A Free, Advanced online design editor with Adobe Photoshop UI supporting PSD, XCF & Sketch formats (Adobe Photoshop, Gimp and Sketch App).
  * [pixlr.com](https://pixlr.com/) — Free online browser editor on the level of commercial ones.
  * [Proto.io](https://www.proto.io) - Create fully interactive UI prototypes without coding. Free tier available when free trial ends. Free tier includes: 1 user, 1 project, 5 prototypes, 100MB online storage and preview in proto.io app.
  * [resizeappicon.com](https://resizeappicon.com/) — A simple service to resize and manage your app icons.
  * [smartmockups.com](https://smartmockups.com/) — Create product mockups, 200 free mockups.
  * [unDraw](https://undraw.co/) - A constantly updated collection of beautiful svg images that you can use completely free and without attribution.
  * [unsplash.com](https://unsplash.com/) - Free stock photos for commercial and noncommercial purposes (do-whatever-you-want license).
  * [vectr.com](https://vectr.com/) — Free Design App for Web + Desktop.
  * [walkme.com](https://www.walkme.com/) — Enterprise Class Guidance and Engagement Platform, free plan 3 walk-thrus up to 5 steps/walk.
  * [Webflow](https://webflow.com) - WYSIWYG web site builder with animations and website hosting. Free for 2 projects.
  * [whimsical.com](https://whimsical.com/) - Collaborative flowcharts, wireframes, sticky notes and mind maps. Create up to 4 free boards.
  * [Zeplin](https://zeplin.io/) — Designer and developer collaboration platform. Show designs, assets and styleguides. Free for 1 project.
  * [Pixelixe](https://pixelixe.com/) — Create and edit engaging and unique graphics and images online.
  * [Responsively App](https://responsively.app) - A free dev-tool for faster and precise responsive web application development.
  * [SceneLab](https://scenelab.io) - Online mockup graphics editor with an ever-expanding collection of free design templates
  * [xLayers](https://xlayers.dev) - Preview and convert Sketch design files into Angular, React, Vue, LitElement, Stencil, Xamarin and more (free and open source at https://github.com/xlayers/xlayers)

## Data Visualization on Maps

   * [carto.com](https://carto.com/) — Create maps and geospatial APIs from your data and public data.
   * [datamaps.world](https://datamaps.world/) — The simple, yet powerful platform that gives you tools to visualize your geospatial data with a free tier.
   * [developers.arcgis.com](https://developers.arcgis.com) — APIs and SDKs for maps, geospatial data storage, analysis, geocoding, routing, and more across web, desktop, and mobile. 1,000,000 free basemap+geocode transactions, 40GB free tile+data storage per month.
   * [Foursquare](https://developer.foursquare.com/) - Location discovery, venue search, and context-aware content from Places API and Pilgrim SDK.
   * [geocod.io](https://www.geocod.io/) — Geocoding via API or CSV Upload. 2,500 free queries/day.
   * [geocodify.com](https://geocodify.com/) — Geocoding and Geoparsing via API or CSV Upload. 10k free queries/month.
   * [giscloud.com](https://www.giscloud.com/) — Visualize, analyze and share geo data online.
   * [gogeo.io](https://gogeo.io/) — Maps and geospatial services with an easy to use API and support for big data.
   * [graphhopper.com](https://www.graphhopper.com/) A free package for developers is offered for Routing, Route Optimization, Distance Matrix, Geocoding, Map Matching.
   * [here](https://developer.here.com/) — APIs and SDKs for maps and location-aware apps. 250k transactions/month for free.
   * [mapbox.com](https://www.mapbox.com/) — Maps, geospatial services and SDKs for displaying map data.
   * [maptiler.com](https://www.maptiler.com/cloud/) — Vector maps, map services and SDKs for map visualisation. Free vector tiles with weekly update and four map styles.
   * [opencagedata.com](https://opencagedata.com) — Geocoding API that aggregates OpenStreetMap and other open geo sources. 2,500 free queries/day.
   * [osmnames](https://osmnames.org/) — Geocoding, search results ranked by the popularity of related Wikipedia page.
   * [positionstack](https://positionstack.com/) - Free geocoding for global places and coordinates. 25.000 Requests per month for personal use.
   * [stadiamaps.com](https://stadiamaps.com/) — Map tiles, routing, navigation, and other geospatial APIs. 2,500 free map views and API requests / day for non-commercial usage and testing.
   * [GeocodeAPI](https://geocodeapi.io) - Geocode API: Address to Coordinate Conversion & Geoparsing based on Pelias. Batch geocoding via CSV. 350000 free requests/month.

## Package Build System

   * [build.opensuse.org](https://build.opensuse.org/) — Package build service for multiple distros (SUSE, EL, Fedora, Debian etc).
   * [copr.fedorainfracloud.org](https://copr.fedorainfracloud.org) — Mock-based RPM build service for Fedora and EL.
   * [help.launchpad.net](https://help.launchpad.net/Packaging) — Ubuntu and Debian build service.

## IDE and Code Editing

   * [Apache Netbeans](https://netbeans.apache.org/) — Development Environment, Tooling Platform and Application Framework.
   * [apiary.io](https://apiary.io/) — Collaborative design API with instant API mock and generated documentation (Free for unlimited API blueprints and unlimited user with one admin account and hosted documentation).
   * [Atom](https://atom.io/) - Atom is a hackable text editor built on Electron.
   * [cacher.io](https://www.cacher.io) — Code snippet organizer with labels and support for 100+ programming languages.
   * [codesnip.com.br](https://codesnip.com.br) — Simple code snippets manager with categories, search and tags. free and unlimit.
   * [cocalc.com](https://cocalc.com/) — (formerly SageMathCloud at cloud.sagemath.com) — Collaborative calculation in the cloud. Browser access to full Ubuntu with built-in collaboration and lots of free software for mathematics, science, data science, preinstalled: Python, LaTeX, Jupyter Notebooks, SageMath, scikitlearn, etc.
   * [codepen.io](https://codepen.io/) — CodePen is a playground for the front end side of the web.
   * [codesandbox.io](https://codesandbox.io/) — Online Playground for React, Vue, Angular, Preact and more.
   * [Eclipse Che](https://www.eclipse.org/che/) - Web based and Kubernetes-Native IDE for Developer Teams with multi-language support. Open Source and community driven. An hosted version is available at [che.openshift.io](https://che.openshift.io/)
   * [fakejson.com](https://fakejson.com/) — FakeJSON helps you quickly generate fake data using its API. Make an API request describing what you want and how you want it. The API returns it all in JSON. Speed up the go to market process for ideas and fake it till you make it.
   * [gitpod.io](https://www.gitpod.io) — Instant, ready-to-code dev environments for GitHub projects. Free for open source.
   * [ide.goorm.io](https://ide.goorm.io) goormIDE is full IDE on cloud. multi-language support, linux-based container via the fully-featured web-based terminal, port forwarding, custom url, real-time collaboration and chat, share link, Git/Subversion support. There are many more features (free tier includes 1GB RAM and 10GB Storage per container, 5 Container slot).
   * [JDoodle](https://www.jdoodle.com) — Online compiler and editor for more than 60 programming languages with a free plan for REST API code compiling up to 200 credits per day.
   * [jetbrains.com](https://jetbrains.com/products.html) — Productivity tools, IDEs and deploy tools (aka [IntelliJ IDEA](https://www.jetbrains.com/idea/), [PyCharm](https://www.jetbrains.com/pycharm/), etc). Free license for students, teachers, Open Source and user groups.
   * [jsbin.com](https://jsbin.com) — JS Bin is another playground and code sharing site of front end web (HTML, CSS and JavaScript. Also supports Markdown, Jade and Sass).
   * [jsfiddle.net](https://jsfiddle.net/) — JS Fiddle is a playground and code sharing site of front end web, support collaboration as well.
   * [JSONPlaceholder](http://jsonplaceholder.typicode.com/) Some REST API endpoints that return some fake data in JSON format. The source code is also available if you would like to run the server locally.
   * [Katacoda](https://katacoda.com) — Interactive learning and training platform for software engineers helping developers learn and companies increase adoption.
   * [micro-jaymock](https://micro-jaymock.now.sh/) - Tiny API mocking microservice for generating fake JSON data.
   * [mockable.io](https://www.mockable.io/) — Mockable is a simple configurable service to mock out RESTful API or SOAP web-services. This online service allows you to quickly define REST API or SOAP endpoints and have them return JSON or XML data.
   * [mockaroo](https://mockaroo.com/) — Mockaroo lets you generate realistic test data in CSV, JSON, SQL, and Excel formats. You can also create mocks for back-end API.
   * [Mocklets](https://mocklets.com) - a HTTP-based mock API simulator, which helps simulate APIs for faster parallel development and more comprehensive testing, with lifetime free tier.
   * [repl.it](https://repl.it/) — A cloud coding environment for various program languages.
   * [stackblitz.com](https://stackblitz.com/) — Online VS Code IDE for Angular & React.
   * [Visual Studio Code](https://code.visualstudio.com/) - Code editor redefined and optimized for building and debugging modern web and cloud applications. Developed by Microsoft for Windows, macOS and Linux.
   * [Visual Studio Community](https://visualstudio.microsoft.com/vs/community/) — Fully-featured IDE with thousands of extensions, cross-platform app development (Microsoft extensions available for download for iOS and Android), desktop, web and cloud development, multi-language support (C#, C++, JavaScript, Python, PHP and more).
   * [VSCodium](https://vscodium.com/) - Community-driven, without telemetry/tracking, and freely-licensed binary distribution of Microsoft’s editor VSCode
   * [wakatime.com](https://wakatime.com/) — Quantified self-metrics about your coding activity, using text editor plugins, limited plan for free.

## Analytics, Events and Statistics

   * [howuku.com](https://howuku.com) — Track user interaction, engagement, and event. Free for up to 5,000 visits/month
   * [amplitude.com](https://amplitude.com/) — 1 million monthly events, up to 2 apps
   * [analytics.google.com](https://analytics.google.com/) — Google Analytics
   * [expensify.com](https://www.expensify.com/) — Expense reporting, free personal reporting approval workflow
   * [getinsights.io](https://getinsights.io) - Privacy-focused, cookie free analytics, free for up to 5k events/month.
   * [heap.io](https://heap.io) — Automatically captures every user action in iOS or web apps. Free for up to 5,000 visits/month
   * [hotjar.com](https://www.hotjar.com/) — Per site: 2,000 pages views/day, 3 heatmaps, data stored for 3 months,...
   * [imprace.com](https://imprace.com/) — Landing page analysis with suggestions to improve bounce rates. Free 5 landing pages/domain
   * [keen.io](https://keen.io/) — Custom Analytics for data collection, analysis and visualization. 50,000 events/month free
   * [metrica.yandex.com](https://metrica.yandex.com/) — Unlimited free analytics
   * [mixpanel.com](https://mixpanel.com/) — Free 25,000 points or 200,000 with their badge on your site
   * [Moesif](https://www.moesif.com) — API analytics for REST and GraphQL. (Free up to 500,000 API calls/mo)
   * [optimizely.com](https://www.optimizely.com) — A/B Testing solution, free starter plan, 1 website, 1 iOS and 1 Android app
   * [quantcast.com](https://www.quantcast.com/products/measure-audience-insights/) — Unlimited free analytics
   * [sematext.com](https://sematext.com/cloud/) — Free for up to 50 K actions/month, 1-day data retention, unlimited dashboards, users, etc.
   * [usabilityhub.com](https://usabilityhub.com/) — Test designs and mockups on real people, track visitors. Free for one user, unlimited tests
   * [heatlyanalytics.com](https://www.heatlyanalytics.com) — Free Heatmap tool to understand UI/UX.
   * [woopra.com](https://www.woopra.com/) — Free user analytics platform for 500K actions, 90 day data retention, 30+ one click integration.

## Visitor Session Recording

   * [FullStory.com](https://www.fullstory.com) — 1,000 sessions/month with 1 month data retention and 3 user seats. More information [here](https://help.fullstory.com/hc/en-us/articles/360020623354-FullStory-Free-Edition).
   * [hotjar.com](https://www.hotjar.com/) — Per site: 2,000 pages views/day, 3 heatmaps, data stored for 3 months,...
   * [inspectlet.com](https://www.inspectlet.com/) — 100 sessions/month free for 1 website
   * [livesession.io](https://livesession.io/) — 1,000 sessions/month free for 1 website
   * [mouseflow.com](https://mouseflow.com/) — 100 sessions/month free for 1 website
   * [mousestats.com](https://www.mousestats.com/) — 100 sessions/month free for 1 website
   * [smartlook.com](https://www.smartlook.com/) — free packages for web and mobile apps (1500 sessions/month), 3 heatmaps, 1 funnel, 1-month data history
   * [usersurge.com](https://www.usersurge.com/) — 250K sessions per month for individuals.

## International Mobile Number Verification API and SDK

  * [cognalys.com](https://cognalys.com/) — Freemium mobile number verification through an innovative and reliable method than using SMS gateway. Free 10 tries and 15 verifications/day
  * [numverify.com](https://numverify.com/) — Global phone number validation and lookup JSON API. 250 API requests/month
  * [veriphone.io](https://veriphone.io/) — Global phone number verification in a free, fast, reliable JSON API. 1000 requests/month

## Payment and Billing Integration

  * [currencyapi.net](https://currencyapi.net/) — Live Currency Rates for Physical and Crypto currencies, delivered in JSON and XML. Free tier offers 1,250 API requests/month.
  * [currencylayer.com](https://currencylayer.com/) — Reliable Exchange Rates and Currency Conversion for your Business, 1,000 API requests/month free
  * [currencystack.io](https://currencystack.io/) — Production-ready real-time exchange rates for 154 currencies.
  * [exchangerate-api.com](https://www.exchangerate-api.com) - An easy to use currency conversion JSON API. Free tier with no request limit.
  * [fraudlabspro.com](https://www.fraudlabspro.com) — Help merchants to prevent payment fraud and chargebacks. Free Micro Plan available with 500 queries/month.
  * [mailpop.in](https://mailpop.in) - Get the most of your Stripe notifications with contextualized information.
  * [vatlayer.com](https://vatlayer.com/) — Instant VAT number validation and EU VAT rates API, free 100 API requests/month

## Docker Related

  * [canister.io](https://canister.io/) — 20 free private repositories for developers, 30 free private repositories for teams to build and store Docker images
  * [Docker Hub](https://hub.docker.com) — One free private repository and unlimited public repositories to build and store Docker images
  * [Gitlab](https://gitlab.com) - Per-repo container registry.  10GB limit.
  * [Play with Docker](https://labs.play-with-docker.com/) — A simple, interactive and fun playground to learn Docker.
  * [quay.io](https://quay.io/) — Build and store container images with unlimited free public repositories
  * [Whales](https://github.com/Gueils/whales) — A tool to automatically dockerize your applications for free.

## Vagrant Related

  * [app.vagrantup.com](https://app.vagrantup.com) - HashiCorp Vagrant Cloud. Vagrant box hosting.
  * [vagrantbox.es](https://www.vagrantbox.es/) — An alternative public box index

## Dev Blogging Sites

  * [dev.to](https://dev.to/) - Where programmers share ideas and help each other grow.
  * [hashnode.com](https://hashnode.com/) — Hassle-free Blogging Software for Developers!.
  * [medium.com](https://medium.com/) — Get smarter about what matters to you.

## Commenting Platforms
  * [ReplyBox](https://getreplybox.com) - ReplyBox, a simple, honest comment system. No ads, no dodgy affiliate links, no fluff.
  * [Staticman](https://staticman.net/) - Staticman is a Node.js application that receives user-generated content and uploads it as data files to a GitHub and/or GitLab repository, using Pull Requests.
  * [GraphComment](https://graphcomment.com/) - GraphComment is a comments platform that helps you build an active community from website’s audience. 
  * [Utterances](https://utteranc.es/) - A lightweight comments widget built on GitHub issues. Use GitHub issues for blog comments, wiki pages and more!
  * [Disqus](https://disqus.com/) - Disqus is a networked community platform used by hundreds of thousands of sites all over the web.


## Screenshot APIs

  * [ApiFlash](https://apiflash.com) — A screenshot API based on Aws Lambda and Chrome. Handles full page, capture timing, viewport dimensions, ...
  * [microlink.io](https://microlink.io/) – It turns any website into data such as metatags normalization, beauty link previews, scraping capabilities or screenshots as a service. 250 reqs/day every day free.
  * [ScreenshotAPI.net](https://screenshotapi.net/) - Screenshot API use one simple API call to generate screenshots of any website. Build to scale and hosted on Google Cloud. Offers 100 free screenshots per month.
  * [screenshotlayer.com](https://screenshotlayer.com/) — Capture highly customizable snapshots of any website. Free 100 snapshots/month
  * [screenshotmachine.com](https://www.screenshotmachine.com/) — Capture 100 snapshots/month, png, gif and jpg, including full-length captures, not only home page
  * [WWW2PNG](https://www2png.com/) - Capture screenshots of any website with basic customization. Includes automatic blockchain anchoring and full page capture. Completely free service.

## Browser based hardware emulation written in Javascript

  * [JsLinux](https://bellard.org/jslinux) — a really fast x86 virtual machine capable of running Linux and Windows 2k.
  * [Jor1k](http://s-macke.github.io/jor1k/demos/main.html) —  a OpenRISC virtual machine capable of running Linux with network support.
  * [v86](https://copy.sh/v86) — a x86 virtual machine capable of running Linux and other OS directly into the browser.
  
## Miscellaneous

  * [Code Time](https://www.software.com/code-time) - an extension for time-tracking and coding metrics in VS Code, Atom, IntelliJ, Sublime Text, and more.
  * [ConfigCat](https://configcat.com) - Cross-platform feature flag service. SDKs for all major languages. Free plan up to 10 flags, 2 environments, 1 product and 5 Million requests per month. Unlimited user seats. Students get 100 flags and 100 Million requests per month for free.
  * [docsapp.io](https://www.docsapp.io/) — Easiest way to publish documentation, free for Open Source
  * [Filly](https://fill.ly) — Boost your web development workflow by reusing manual actions done previously on your app. Form filler for improved team collaboration.
  * [FOSSA](https://fossa.com/) - Scalable, end-to-end management for third-party code, license compliance and vulnerabilities.
  * [fullcontact.com](https://www.fullcontact.com/developer/pricing/) — Help your users know more about their contacts by adding social profile into your app. 500 free Person API matches/month
  * [http2.pro](https://http2.pro) — HTTP/2 protocol readiness test and client HTTP/2 support detection API.
  * [newreleases.io](https://newreleases.io/) - Receive notifications on email, Slack, Telegram, Discord and custom webhooks for new releases from GitHub, GitLab, Bitbucket, Python PyPI, Java Maven, Node.js NPM, Node.js Yarn, Ruby Gems, PHP Packagist, .NET NuGet, Rust Cargo and Docker Hub.
  * [PDFMonkey](https://www.pdfmonkey.io/) — Manage PDF templates in a dashboard, call the API with dynamic data, download your PDF. Offers 1000 free documents per month.
  * [readme.com](https://readme.com/) — Beautiful documentation made easy, free for Open Source: see [here](https://readme.readme.io/docs/open-source).
  * [ReqBin](https://www.reqbin.com/) — Post HTTP Requests Online. Popular Request Methods include GET, POST, PUT, DELETE, and HEAD. Supports Headers and Token Authentication. Includes a basic login system for saving your requests.
  * [superfeedr.com](https://superfeedr.com/) — Real-time PubSubHubbub compliant feeds, export, analytics. Free with less customization
  * [SurveyMonkey.com](https://www.surveymonkey.com) — Create online surveys. Analyze the results online.  Free plan allows only 10 questions and 100 responses per survey.
  * [videoinu](https://videoinu.com) — Create and edit screen recordings and other videos online

## Other Free Resources

  * [education.github.com](https://education.github.com/pack) — Collection of free services for students. Registration required
  * [Framacloud](https://degooglisons-internet.org/en/list/) — A list of Free/Libre Open Source Software and SaaS by the French non-profit [Framasoft](https://framasoft.org/en/).
  * [getawesomeness](https://getawesomeness.herokuapp.com) — Retrieve all amazing awesomeness from GitHub... a must see
  * [github.com — FOSS for Dev](https://github.com/tvvocold/FOSS-for-Dev) — A hub of free and Open Source software for developers
