# [free-for.dev](https://free-for.dev)

Developers and Open Source authors now have a massive amount of services offering free tiers, but it can be hard to find them all in order to make informed decisions.

This is a list of software (SaaS, PaaS, IaaS, etc.) and other offerings that have free tiers for developers.

The scope of this particular list is limited to things infrastructure developers (System Administrator, DevOps Practitioners, etc.) are likely to find useful. We love all the free services out there, but it would be good to keep it on topic. It's a bit of a grey line at times so this is a bit opinionated; do not be offended if I do not accept your contribution.

This list is the result of Pull Requests, reviews, ideas and work done by 500+ people, you too can help by sending [Pull Requests](https://github.com/ripienaar/free-for-dev) to add more services or by removing ones whose offerings have changed or been retired.

*NOTE:* This list is only for as-a-Service offerings, not for self-hosted software. For a service to be eligible it has to offer a Free Tier and not just a free trial. If the Free Tier is time bucketed it has to be at least a year.

Table of Contents
=================

   * [Major Cloud Providers' Always-Free Limits](#major-cloud-providers)
   * [Analytics, Events and Statistics](#analytics-events-and-statistics)
   * [APIs, Data and ML](#apis-data-and-ml)
   * [Artifact Repos](#artifact-repos)
   * [Testing](#testing)
   * [BaaS](#baas)
   * [CDN and Protection](#cdn-and-protection)
   * [CI and CD](#ci-and-cd)
   * [Code Quality](#code-quality)
   * [Code Search and Browsing](#code-search-and-browsing)
   * [Crash and Exception Handling](#crash-and-exception-handling)
   * [Data Visualization on Maps](#data-visualization-on-maps)
   * [DBaaS](#dbaas)
   * [Design and UI](#design-and-ui)
   * [DNS](#dns)
   * [Docker Related](#docker-related)
   * [Email](#email)
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
   * [Search](#search)
   * [Security and PKI](#security-and-pki)
   * [Source Code Repos](#source-code-repos)
   * [Storage and Media Processing](#storage-and-media-processing)
   * [STUN, WebRTC, Web Socket Servers and Other Routers](#stun-webrtc-web-socket-servers-and-other-routers)
   * [Tools for Teams and Collaboration](#tools-for-teams-and-collaboration)
   * [Translation Management](#translation-management)
   * [Vagrant Related](#vagrant-related)
   * [Visitor Session Recording](#visitor-session-recording)
   * [Web Hosting](#web-hosting)
   * [Dev Blogging Sites](#dev-blogging-sites)

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
    * Google Kubernetes Engine - No cluster management fee for clusters of all sizes. Each user node is charged at standard Compute Engine pricing
    * BigQuery - 1 TB of querying per month, 10 GB of storage each month
    * Cloud Build - 120 build-minutes per day
    * Cloud Source Repositories - Up to 5 Users, 50 GB Storage, 50 GB Egress
    * Full, detailed list - https://cloud.google.com/free/docs/gcp-free-tier#always-free-usage-limits

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
    * Kubernetes - Free cluster with 1 worker node
    * Cloud Functions - 5 million executions per month
    * Object Storage - 25GB per month
    * Cloudant database - 1 GB of data storage
    * Db2 database - 100MB of data storage
    * API Connect - 50,000 API calls per month
    * Availability Monitoring - 3 million data points per month
    * Log Analysis - 500MB of daily log
    * Full, detailed list - https://www.ibm.com/cloud/free/

## Source Code Repos

  * [github.com](https://github.com/) — Unlimited public repositories and unlimited private repositories (up to 3 collaborators) with Pipelines for CI/CD
  * [bitbucket.org](https://bitbucket.org/) — Unlimited public and private Git repos for up to 5 users with Pipelines for CI/CD
  * [gitlab.com](https://about.gitlab.com/) — Unlimited public and private Git repos with unlimited collaborators and 10 GB space per repo
  * [pijul.com](https://pijul.com/) - Unlimited free and open source distributed version control system. Its distinctive feature is to be based on a sound theory of patches, which makes it easy to learn and use, and really distributed. Solves many problems of git/hg/svn/darcs.
  * [chiselapp.com](http://chiselapp.com/) — Unlimited public and private Fossil repositories
  * [Azure DevOps](https://azure.microsoft.com/services/devops/) — Unlimited private repos (Git and TFS) for up to 5 users/team
  * [plasticscm.com](https://plasticscm.com/) — Free for individuals, OSS and nonprofit organizations
  * [codebasehq.com](https://www.codebasehq.com/) — One free project with 100 MB space and 2 users
  * [NotABug](https://notabug.org) — NotABug.org is a free-software code collaboration platform for freely licensed projects, Git-based
  * [perforce.com](https://www.perforce.com/products/helix-teamhub) — Free 1GB Cloud and  Git, Mercurial, or SVN repositories.
  * [projectlocker.com](https://projectlocker.com) — One free private project (Git and Subversion) with 50 MB space
  * [ionicframework.com](https://ionicframework.com/appflow) - Repo and tools to develop applications with Ionic, also you have an ionic repo
  * [gitea.com](https://www.gitea.com/) - Unlimited public and private Git repos
  * [codeberg.org](https://codeberg.org/) - Unlimited public and private Git repos

## APIs, Data and ML

  * [algorithmia.com](https://algorithmia.com/) — Host algorithms for free. Includes free monthly allowance for running algorithms. Now with CLI support
  * [ApiFlash](https://apiflash.com) — A screenshot API based on Aws Lambda and Chrome. Handles full page, capture timing, viewport dimensions, ...
  * [Apify](https://www.apify.com/) — Web scraping and automation platform that lets you create an API extracting websites data. Free tier with 10k monthly crawls and 7 days data retention.
  * [Beeceptor](https://beeceptor.com) - Mock a rest API in seconds, fake API response and much more. Free 50 requests per day, public dashboard, open endpoints (anyone having link to the dashboard can view requests and responses).
  * [Bearer.sh](https://www.bearer.sh) - API Integrations built in minutes, monitored in real-time. With a universal API client, call any API in 2 minutes and monitor all your integrations from a simple dashboard.
  * [bigml.com](https://bigml.com/) — Hosted machine learning algorithms. Unlimited free tasks for development, limit of 16 MB data/task
  * [Calendarific](https://calendarific.com) - Enterprise-grade Public holiday API service for over 200 countries. Free plan includes 1000 calls per month.
  * [Clarifai](https://www.clarifai.com) — Image API for custom face recognition and detection. Able to train AI models. Free plan has 5000 calls per month.
  * [Colaboratory](https://colab.research.google.com) — Free web-based Python notebook environment with Nvidia Tesla K80 GPU.
  * [Diggernaut](https://www.diggernaut.com/) — Cloud based web scraping and data extraction platform for turning any website to the dataset or to work with it as with an API. Free plan includes 5K page requests monthly.
  * [dominodatalab.com](https://www.dominodatalab.com) — Data science with support for Python, R, Spark, Hadoop, MATLAB and others
  * [dreamfactory.com](https://dreamfactory.com/) — Open source REST API backend for mobile, web, and IoT applications. Hook up any SQL/NoSQL database, file storage system, or external service and it instantly creates a comprehensive REST API platform with live documentation, user management,...
  * [FraudLabs Pro](https://www.fraudlabspro.com) — Screen an order transaction for credit card payment fraud. This REST API will detect all possible fraud traits based on the input parameters of an order. Free Micro plan has 500 transactions per month.
  * [FreeGeoIP.app](https://freegeoip.app/) - Completely free Geo IP information (JSON, CSV, XML). No registration required, 15000 queries per hour rate limit.
  * [IP Geolocation](https://ipgeolocation.io/) — IP Geolocation API - Forever free plan for developers with 30k requests per month (1k/day) limit.
  * [IP2Location](https://www.ip2location.com) — Freemium IP geolocation service. LITE database is available for free download. Import the database in server and perform local query to determine city, coordinates and ISP information.
  * [IPinfo](https://ipinfo.io/) — Fast, accurate, and free (up to 100k/month) IP address data API. Offers APIs with details on geolocation, companies, carriers, IP ranges, domains, abuse contacts, and more. All paid APIs can be trialed for free.
  * [IPList](https://www.iplist.cc) — Lookup details about any IP address, such as Geo IP information, tor addresses, hostnames and ASN details. Free for personal and business users.
  * [IPTrace](https://iptrace.io) — An embarrassingly simple API that provides reliable and useful IP geolocation data for your business.
  * [konghq.com/](https://konghq.com/) — API Marketplace and powerful tools for private and public APIs. With the free tier, some features are limited such as monitoring, alerting and support
  * [MailboxValidator](https://www.mailboxvalidator.com) — Email verification service using real mail server connection to confirm valid email. Free API plan has 300 verifications per month.
  * [microlink.io](https://microlink.io/) – It turns any website into data such as metatags normalization, beauty link previews, scraping capabilities or screenshots as a service. 250 reqs/day every day free.
  * [monkeylearn.com](https://monkeylearn.com/) — Text analysis with machine learning, free 300 queries/month
  * [myfakeapi.com](https://myfakeapi.com) — Free serverless API mocking service for developers
  * [OCR.Space](https://ocr.space/) — An OCR API which parses image and pdf files returning the text results in JSON format. 25,000 requests per month free.
  * [parsehub.com](https://parsehub.com/) — Extract data from dynamic sites, turn dynamic websites into APIs, 5 projects free
  * [Pixela](https://pixe.la/) - Free daystream database service. All operations are performed by API. Visualization with heat maps and line graphs is also possible.
  * [Postman](https://postman.com) — Simplify workflows and create better APIs – faster – with Postman, a collaboration platform for API development. Use the Postman App for free forever. Postman cloud features are also free forever with certain limits.
  * [Postwoman](https://postwoman.io) - API request builder - A free, fast, and beautiful alternative to Postman.
  * [ProxyCrawl](https://proxycrawl.com/) — Crawl and scrape websites without the need of proxies, infrastructure or browsers. We solve captchas for you and prevent you being blocked. The first 1000 calls are free of charge.
  * [RequestBin.com](https://requestbin.com) — Create a free endpoint to which you can send HTTP requests. Any HTTP requests sent to that endpoint will be recorded with the associated payload and headers so you can observe requests from webhooks and other services.
  * [restlet.com](https://restlet.com/products/apispark/) — APISpark enables any API, application or data owner to become an API provider in minutes via an intuitive browser interface
  * [Releaseflags](https://releaseflags.com) - Feature Flags should be available for every developer at a low-cost. Releaseflags offers free releaseflags for single developers and a low-cost plan for startups.
  * [ROBOHASH](https://robohash.org/) - Web service to generate unique (cool :) images from any text.
  * [scrapinghub.com](https://scrapinghub.com) — Data scraping with visual interface and plugins. Free plan includes unlimited scraping on a shared server
  * [ScrapingNinja](https://www.scrapingninja.co/) — Handle JS rendering, Chrome Headless, Proxy rotation and CAPTCHAs solving all in one place. The first 1000 are free of charge, no credit card required.
  * [Scraper API](https://www.scraperapi.com/) — Cloud based web scraping API handles proxies, browsers, and CAPTCHAs. Scrape any web page with a simple API call. Get started with 1000 free API calls/month.
  * [ScreenshotAPI.net](https://screenshotapi.net/) - Screenshot API use one simple API call to generate screenshots of any website. Build to scale and hosted on Google Cloud. Offers 100 free screenshots per month.
  * [shrtcode API](https://shrtco.de/docs) - Free URL Shortening API without authorisation and no request limits
  * [tamber](https://tamber.com) — Put deep-learning powered recommendations in your app. Free 5k monthly active users.
  * [Time Door](https://timedoor.io) - A time series analysis API
  * [Webhook.site](https://webhook.site) - Easily test HTTP webhooks with this handy tool that displays requests instantly.
  * [wit.ai](https://wit.ai/) — NLP for developers
  * [wolfram.com](http://wolfram.com/language/) — Built-in knowledge-based algorithms in the cloud
  * [wrapapi.com](https://wrapapi.com/) — Turn any website into a parameterized API. 30k API calls per month
  * [Zenscrape](https://zenscrape.com/web-scraping-api) — Web scraping API with headless browsers, residentials IPs and simple pricing. 1000 free API calls/month, extra free credits for students and non-profits
  * [DB Designer](https://www.dbdesigner.net/) — Cloud based Database schema design and modeling tool with a free starter plan of 2 Database models and 10 tables per model.
  * [GeoDataSource](https://www.geodatasource.com) — Location search service lookup for city name by using latitude and longitude coordinate. Free API queries up to 500 times per month.

## Artifact Repos

 * [bintray.com](https://bintray.com/) — JFrog Bintray hosts Open Source projects for free, and supports Docker, Maven, NuGet, npm, Debian, RPM, Conan, Vagrant, Opkg, yum, and also home to [JCenter](https://bintray.com/bintray/jcenter) the most comprehensive collection of Maven artifacts.
 * [central.sonatype.org](https://central.sonatype.org) — The default artifact repository for Apache Maven, SBT and other build systems.
 * [packagecloud.io](https://packagecloud.io) — Easy to use repository hosting for: Maven, RPM, DEB, PyPi and RubyGem packages (has free tier).
 * [cloudsmith.io](https://cloudsmith.io) — Simple, secure and centralised repository service for Java/Maven, RedHat, Debian, Python, Ruby, Vagrant +more. Free tier + free for open source.
 * [jitpack.io](https://jitpack.io/) — Maven repository for JVM and Android projects on GitHub, free for public projects.
 * [cloudrepo.io](https://cloudrepo.io) - Cloud based, private and public, Maven and PyPi repositories. Free for open source projects.

## Tools for Teams and Collaboration

  * [Filestash](https://www.filestash.app) — A Dropbox-like file manager that connects to a range of protocols and platforms: S3, FTP, SFTP, Minio, Git, WebDAV, Backblaze, LDAP and more.
  * [GitDuck](https://gitduck.com/) — Private live coding and remote pair programming for distributed teams. Open-source tool
  * [scinote.net](https://scinote.net) — Scientific data management and team collaboration. One Team with unlimited number of users, backup and 1 GB storage space
  * [whereby.com](https://whereby.com/) — One click video conversations, for free (formerly known as appear.in)
  * [meet.jit.si](https://meet.jit.si/) — One click video conversations, screen sharing, for free
  * [flowdock.com](https://www.flowdock.com/) — Chat and inbox, free for teams up to 5
  * [slack.com](https://slack.com/) — Free for unlimited users with some feature limitations
  * [twist.com](https://twist.com) — An asynchronous-friendly team communication app where conversations stay organized and on-topic. Free and Unlimited plans available. Discounts provided for eligible teams.
  * [gitter.im](https://gitter.im/) — Chat, for GitHub. Unlimited public and private rooms, free for teams up to 25
  * [Discord](https://discordapp.com/) — Chat with public/private Rooms & VoIP Service. Free for unlimited users.
  * [hangouts.google.com](https://hangouts.google.com/) — One place for all your conversations, for free, need a Google account
  * [seafile.com](https://www.seafile.com/) — Private or cloud storage, file sharing, sync, discussions. Private version is full. Cloud version has just 1 GB
  * [yammer.com](https://www.yammer.com/) — Private social network standalone or for MS Office 365. Free with a bit less admin tools and user management features
  * [helpmonks.com](https://helpmonks.com/) — Shared inbox for teams, free for Open Source and nonprofit organizations
  * [typetalk.com](https://www.typetalk.com/) — Share and discuss ideas with your team through instant messaging on the web or on your mobile
  * [talky.io](https://talky.io/) — Free group video chat. Anonymous. Peer‑to‑peer. No plugins, signup, or payment required
  * [helplightning.com](https://www.helplightning.com/) — Help over video with augmented reality. Free without analytics, encryption, support
  * [evernote.com](https://evernote.com/) — Tool for organizing information. Share your notes and work together with others
  * [cally.com](https://cally.com/) — Find the perfect time and date for a meeting. Simple to use, works great for small and large groups.
  * [zoom.us](https://zoom.us/) — Secure Video and Web conferencing, add-ons available. Free limited to 40 minutes
  * [ideascale.com](https://ideascale.com/) — Allow clients to submit ideas and vote, free for 25 members in 1 community
  * [wistia.com](https://wistia.com/) — Video hosting with viewer analytics, HD video delivery and marketing tools to help understand your visitors, 25 videos and Wistia branded player
  * [flock.com](https://flock.com) — A faster way for your team to communicate. Free Unlimited Messages, Channels, Users, Apps & Integrations
  * [Igloo](https://www.igloosoftware.com/) — Internal portal for sharing documents, blogs and calendars etc. Free for up to 10 users.
  * [riot.im](https://about.riot.im/) — A decentralized communication tool built on Matrix. Group chats, direct messaging, encrypted file transfers, voice and video chats, and easy integration with other services.
  * [Microsoft Teams](https://products.office.com/microsoft-teams/free) — Microsoft Teams is a chat-based digital hub that brings conversations, content, and apps together in one place all from a single experience. Free for up to 300 users.
  * [featurepeek.com](https://featurepeek.com) - Cloud provider-agnostic front-end feature environments with team collaboration tools built-in. Works with static and Dockerized front-ends. Free for public repositories.
  * [Spectrum](https://spectrum.chat/) - Create public or private communities for free.
  * [StatusPile](https://www.statuspile.com/) - A status page of status pages. Track the status pages of your upstream providers.
  * [Pendulums](https://pendulums.io/) - Pendulums is a free time tracking tool which helps you to manage your time in a better manner with an easy to use interface and useful statistics.
  * [Notion](https://www.notion.so/) - Notion is a note-taking and collaboration application with markdown support that also integrates tasks, wikis, and databases. The company describes the app as an all-in-one workspace for note-taking, project management and task management. In addition to cross-platform apps, it can be accessed via most web browsers.
  * [Tadum](https://tadum.app) - Meeting agenda and minutes app designed for recurring meetings, free for teams up to 10
  * [Tefter](https://tefter.io) - Bookmarking app with a powerful Slack integration. Free for open-source teams.

## Code Quality

  * [codescene.io](https://codescene.io/) - CodeScene prioritizes technical debt based on how the developers work with the code and visualizes organizational factors like team coupling and system mastery. Free for Open Source.
  * [dareboost](https://dareboost.com) - 5 free analysis report for web performance, accessibility, security each month
  * [hiberly.com](https://hiberly.com) - Tech debt toolkit for developers - grabs feedback from engineers after each merge, then aggregates this to quantify and highlight tech debt in the codebase. Free for use in retrospectives for up to 12 months.
  * [tachikoma.io](https://tachikoma.io/) — Dependency Update for Ruby, Node.js, Perl projects, free for Open Source
  * [codeclimate.com](https://codeclimate.com/) — Automated code review, free for Open Source and unlimited organisation-owned private repos (up to 4 collaborators). Also free for students and institutions.
  * [houndci.com](https://houndci.com/) — Comments on GitHub commits about code quality, free for Open Source
  * [coveralls.io](https://coveralls.io/) — Display test coverage reports, free for Open Source
  * [scrutinizer-ci.com](https://scrutinizer-ci.com/) — Continuous inspection platform, free for Open Source
  * [codecov.io](https://codecov.io/) — Code coverage tool (SaaS), free for Open Source and 1 free private repo
  * [insight.sensiolabs.com](https://insight.sensiolabs.com/) — Code Quality for PHP/Symfony projects, free for Open Source
  * [codacy.com](https://www.codacy.com/) — Automated code reviews for PHP, Python, Ruby, Java, JavaScript, Scala, CSS and CoffeeScript, free for unlimited public and private repositories
  * [gocover.io](https://gocover.io/) — Code coverage for any [Go](https://golang.org/) package
  * [goreportcard.com](https://goreportcard.com/) — Code Quality for Go projects, free for Open Source
  * [scan.coverity.com](https://scan.coverity.com/) — Static code analysis for Java, C/C++, C# and JavaScript, free for Open Source
  * [webceo.com](https://www.webceo.com/) — SEO tools but with also code verifications and different type of advices
  * [zoompf.com](https://zoompf.com/) — Fix the performance of your web sites, detailed analysis
  * [gtmetrix.com](https://gtmetrix.com/) — Reports and thorough recommendations to optimize websites
  * [browserling.com](https://www.browserling.com/) — Live interactive cross-browser testing, free only 3 minutes sessions with MS IE 9 under Vista at 1024 x 768 resolution
  * [shields.io](https://shields.io) — Quality metadata badges for open source projects
  * [beanstalkapp.com](https://beanstalkapp.com/) — A complete workflow to write, review and deploy code), free account for 1 user and 1 repository with 100 MB of storage
  * [testanywhere.co](https://testanywhere.co/) — Automatic test website or web app continuously and catch bugs in the early stages, free 1,000 tests/month
  * [gerrithub.io](https://review.gerrithub.io/) — Gerrit code review for GitHub repositories for free
  * [reviewable.io](https://reviewable.io/) — Code review for GitHub repositories, free for public or personal repos
  * [sonarcloud.io](https://sonarcloud.io) — Automated source code analysis for Java, JavaScript, C/C++, C#, VB.NET, PHP, Objective-C, Swift, Python, Groovy and even more languages, free for Open Source
  * [golangci.com](https://golangci.com) — Automated Go (golang) code review service for GitHub pull requests.
  * [lgtm.com](https://lgtm.com) — Continuous security analysis for Java, Python, JavaScript, TypeScript, C#, C and C++, free for Open Source
  * [deepscan.io](https://deepscan.io) — Advanced static analysis for automatically finding runtime errors in JavaScript code, free for Open Source
  * [Imgbot](https://github.com/marketplace/imgbot) — Imgbot is a friendly robot that optimizes your images and saves you time. Optimized images mean smaller file sizes without sacrificing quality. It's free for open source.
  * [Typo CI](https://github.com/marketplace/typo-ci) — Typo CI reviews your Pull Requests and commits for spelling mistakes, free for Open Source.
  * [DeepSource](https://deepsource.io/) - DeepSource continuously analyzes source code changes and finds issues categorized under security, performance, anti-patterns, bug-risks, documentation and style. For Python and Go. Free for open source.

## Code Search and Browsing

  * [codota.com](https://www.codota.com/) — Codota helps developers create better software, faster by providing insights learned from all the code in the world. Plugin available.
  * [libraries.io](https://libraries.io/) — Search and dependency update notifications for 32 different package managers, free for open source
  * [sourcegraph.com](https://about.sourcegraph.com/) — Java, Go, Python, Node.js, etc., code search/cross-references, free for Open Source
  * [searchcode.com](https://searchcode.com/) — Comprehensive text-based code search, free for Open Source

## CI and CD

  * [ligurio/awesome-ci](https://github.com/ligurio/awesome-ci) — Comparison of Continuous Integration services
  * [Azure Pipelines](https://azure.microsoft.com/services/devops/pipelines/) — 10 free parallel jobs with unlimited minutes for open source for Linux, macOS, and Windows
  * [codefresh.io](https://codefresh.io) — Free-for-Life plan: 1 build, 1 environment, shared servers, unlimited public repos
  * [codeship.com](https://codeship.com/) — 100 private builds/month, 5 private projects, unlimited for Open Source
  * [circleci.com](https://circleci.com/) — Free for one concurrent build
  * [stackahoy.io](https://stackahoy.io) — 100% free. Unlimited deployments, branches and builds
  * [travis-ci.org](https://travis-ci.org/) — Free for public GitHub repositories
  * [semaphoreci.com](https://semaphoreci.com/) — Free for Open Source, 100 private builds per month
  * [shippable.com](https://app.shippable.com/) — 150 private builds/month, free for 1 build container, private and public repos
  * [appveyor.com](https://www.appveyor.com/) — CD service for Windows, free for Open Source
  * [deployhq.com](https://www.deployhq.com/) — 1 project with 10 daily deployments (30 build minutes/month)
  * [styleci.io](https://styleci.io/) — Public GitHub repositories only
  * [buddybuild.com](https://www.buddybuild.com/) — Build, deploy and gather feedback for your iOS and Android apps in one seamless, iterative system
  * [gitlab.com](https://about.gitlab.com/product/continuous-integration/) — Create pipelines directly from Git repositories using GitLab's CI service.  2,000min/mo
  * [buddy.works](https://buddy.works/) — A CI/CD with 5 free projects and 1 concurrent runs (120 executions/month)
  * [bitrise.io](https://www.bitrise.io/) — A CI/CD for mobile apps, native or hybrid. With 200 free builds/month 10 min build time and two team members. OSS projects get 45 min build time, +1 concurrency and unlimited team size.
  * [AccessLint](https://github.com/marketplace/accesslint) — AccessLint brings automated web accessibility testing into your development workflow. It's free for open source and education purposes.

## Testing

  * [gridlastic.com](https://www.gridlastic.com/) — Selenium Grid testing with free plan up to 4 simultaneous selenium nodes/10 grid starts/4,000 test minutes/month
  * [saucelabs.com](https://saucelabs.com/) — Cross browser testing, Selenium testing and mobile testing, [free for Open Source](https://saucelabs.com/open-source)
  * [crossbrowsertesting.com](https://crossbrowsertesting.com) - Manual, Visual, and Selenium Browser Testing in the cloud - [free for Open Source](https://crossbrowsertesting.com/open-source)
  * [browserstack.com](https://www.browserstack.com/) — Manual and automated browser testing, [free for Open Source](https://www.browserstack.com/open-source?ref=pricing)
  * [everystep-automation.com](https://www.everystep-automation.com/) — Records and replays all steps made in a web browser and creates scripts,... free with fewer options
  * [Applitools.com](https://applitools.com/) — smart visual validation for web, native mobile and desktop apps. Integrates with almost all automation solutions (like Selenium and Karma) and remote runners (Sauce Labs, Browser Stack). free for open source. A free tier for a single user with limited checkpoints per week.
  * [checkbot.io](https://www.checkbot.io/) — Browser extension that tests if your website follows 50+ SEO, speed and security best practices. Free tier for smaller websites.
  * [testingbot.com](https://testingbot.com/) — Selenium Browser and Device Testing, [free for Open Source](https://testingbot.com/open-source)
  * [tesults.com](https://www.tesults.com) — Test results reporting and test case management. Integrates with popular test frameworks. Open Source software developers, individuals, educators, and small teams getting started can request discounted and free offerings beyond basic free project.
  * [cypress.io](https://www.cypress.io/) - Fast, easy and reliable testing for anything that runs in a browser. Cypress Test Runner is always free and open source with no restrictions and limitations. Cypress Dashboard is free for open source projects for up to 5 users.
  * [percy.io](https://percy.io) - Add visual testing to any web app, static site, style guide, or component library.  10 team members, Demo app and unlimited projects, 5,000 snapshots / month.

## Security and PKI

  * [meterian.io](https://www.meterian.io/) - Monitor Java, Javascript, .NET, Scala, Ruby and NodeJS projects for security vulnerabilities in dependencies. Free for one private project, unlimited projects for open source.
  * [pyup.io](https://pyup.io) — Monitor Python dependencies for security vulnerabilities and update them automatically. Free for one private project, unlimited projects for open source.
  * [threatconnect.com](https://threatconnect.com) — Threat intelligence: It is designed for individual researchers, analysts and organizations who are starting to learn about cyber threat intelligence. Free up to 3 Users
  * [crypteron.com](https://www.crypteron.com/) — Cloud-first, developer-friendly security platform prevents data breaches in .NET and Java applications
  * [snyk.io](https://snyk.io) — Can find and fix known security vulnerabilities in your open source dependencies. Unlimited tests and remediation for open source projects. Limited to 200 tests/month for your private projects.
  * [letsencrypt.org](https://letsencrypt.org/) — Free SSL Certificate Authority with certs trusted by all major browsers
  * [globalsign.com](https://www.globalsign.com/en/ssl/ssl-open-source/) — Free SSL certificates for Open Source
  * [Okta](https://developer.okta.com/) — User management, authentication and authorization. Free for up to 1000 monthly active users.
  * [auth0.com](https://auth0.com/) — Hosted free for development SSO. Up to 2 social identity providers for closed-source projects.
  * [ringcaptcha.com](https://ringcaptcha.com/) — Tools to use phone number as id, available for free
  * [ssllabs.com](https://www.ssllabs.com/ssltest/) — Very deep analysis of the configuration of any SSL web server
  * [qualys.com](https://www.qualys.com/community-edition) — Find web app vulnerabilities, audit for OWASP Risks
  * [alienvault.com](https://www.alienvault.com/open-threat-exchange/reputation-monitor) — Uncovers compromised systems in your network
  * [duo.com](https://duo.com/) — Two-factor authentication (2FA) for website or app. Free for 10 users, all authentication methods, unlimited, integrations, hardware tokens
  * [tinfoilsecurity.com](https://www.tinfoilsecurity.com/) — Automated vulnerability scanning. Free plan allows weekly XSS scans
  * [ponycheckup.com](https://www.ponycheckup.com/) — An automated security checkup tool for Django websites
  * [foxpass.com](https://www.foxpass.com/) — Hosted LDAP and RADIUS. Easy per-user logins to servers, VPNs and wireless networks. Free for 10 users
  * [opswat.com](https://www.opswat.com/) — Security Monitoring of computers, devices, applications, configurations,... Free 25 users and 30 days history
  * [bitninja.io](https://bitninja.io/) — Botnet protection through a blacklist, free plan only reports limited information on each attack
  * [onelogin.com](https://www.onelogin.com/) — Identity as a Service (IDaaS), Single Sign-On Identity Provider, Cloud SSO IdP, 3 company apps and 5 personal apps, unlimited users
  * [logintc.com](https://www.logintc.com/) — Two-factor authentication (2FA) by push notifications, free for 10 users, VPN, Websites and SSH
  * [report-uri.io](https://report-uri.io/) — CSP and HPKP violation reporting
  * [cloudsploit.com](https://cloudsploit.com/) — Amazon Web Services (AWS) security and compliance auditing and monitoring
  * [Have I been pwned?](https://haveibeenpwned.com) — REST API for fetching the information on the breaches.
  * [Internet.nl](https://internet.nl) — Test for modern Internet Standards like IPv6, DNSSEC, HTTPS, DMARC, STARTTLS and DANE
  * [Mozilla Observatory](https://observatory.mozilla.org/) — Find and fix security vulnerabilities in your site.
  * [Shieldfy](https://shieldfy.io) — Web application firewall and vulnerability detection for developers, free plan up to 100k requests per month.
  * [Sqreen](https://www.sqreen.com/) — Application security monitoring and protection (RASP, WAF and more) for web applications and APIs. Free for 1 app and 3 million requests.
  * [Sucuri SiteCheck](https://sitecheck.sucuri.net) - Free website security check and malware scanner
  * [Protectumus](https://protectumus.com) - Free website security check, site antivirus and server firewall (WAF). Email and SMS notifications for registered users.

## Management System

  * [bitnami.com](https://bitnami.com/) — Deploy prepared apps on IaaS. Management of 1 AWS micro instance free
  * [jamf.com](https://www.jamf.com/) —  Device management for iPads, iPhones and Macs, 3 devices free
  * [moss.sh](https://moss.sh) - Help developers deploy and manage their web apps and servers. Free up to 25 git deployments per month

## Messaging
  * [cloudamqp.com](https://www.cloudamqp.com/) — RabbitMQ as a Service. Little Lemur plan: max 1 million messages/month, max 20 concurrent connections, max 100 queues, max 10,000 queued messages, multiple nodes in different AZ's
  * [pusher.com](https://pusher.com/) — Realtime messaging service. Free for up to 100 simultaneous connections and 200,000 messages/day
  * [synadia.com](https://synadia.com/ngs) — [NATS.io](https://nats.io) as a service. Global, AWS, GCP, and Azure. Free forever with 4k msg size, 50 active connections and 5GB of data per month.


## Log Management

  * [bugfender.com](https://bugfender.com/) — Free up to 100k log lines/day with 24 hours retention
  * [humio.com](https://www.humio.com/) — Free up to 2 GB/day with 7 days retention
  * [logentries.com](https://logentries.com/) — Free up to 5 GB/month with 7 days retention
  * [loggly.com](https://www.loggly.com/) — Free for a single user, see the lite option
  * [logz.io](https://logz.io/) — Free up to 3 GB/day, 3 days retention
  * [papertrailapp.com](https://papertrailapp.com/) — 48 hours search, 7 days archive, 100 MB/month
  * [rollbar.com](https://rollbar.com) — Free up to 5000 events/month, 30 days retention
  * [sematext.com](https://sematext.com/logsene) — Free up to 500 MB/day, 7 days retention
  * [sumologic.com](https://www.sumologic.com/) — Free up to 500 MB/day, 7 days retention
  * [splunk.com](https://www.splunk.com) - Free for a single user, 500 MB/day

## Translation Management

  * [lingohub.com](https://lingohub.com/) — Free up to 3 users, always free for Open Source
  * [webtranslateit.com](https://webtranslateit.com/) — Free up to 500 strings
  * [transifex.com](https://www.transifex.com/) — Free for Open Source
  * [oneskyapp.com](https://www.oneskyapp.com/) — Limited free edition for up to 5 users, free for Open Source
  * [crowdin.com](https://crowdin.com/) — Unlimited projects, unlimited strings and collaborators for Open Source
  * [Loco](https://localise.biz/) — Free up to 2000 translations, Unlimited translators, 10 languages/project, 1000 translatable assets/project
  * [POEditor](https://poeditor.com/) — Free up to 1000 strings

## Monitoring

  * [instrumentalapp.com](https://instrumentalapp.com) - Beautiful and easy-to-use application and server monitoring with up to 500 metrics and 3 hours of data visibility for free
  * [gitential.com](https://gitential.com) — Software Development Analytics platform. Free: unlimited public repositories, unlimited users, free trial for private repos. On-prem version available for enterprise.
  * [cloudsploit.com](https://cloudsploit.com) — AWS security and configuration monitoring. Free: unlimited on-demand scans, unlimited users, unlimited stored accounts. Subscription: automated scanning, API access, etc.
  * [elastic.co](https://www.elastic.co/solutions/apm) — Instant performance insights for JS developers. Free with 24 hours data retention
  * [appneta.com](https://www.appneta.com/) — Free with 1-hour data retention
  * [thousandeyes.com](https://www.thousandeyes.com/) — Network and user experience monitoring. 3 locations and 20 data feeds of major web services free
  * [datadoghq.com](https://www.datadoghq.com/) — Free for up to 5 nodes
  * [freshworks.com](https://www.freshworks.com/website-monitoring/) — Monitor 50 URLs at 1-minute interval with 10 Global locations and 5 Public status pages for Free
  * [nodequery.com](https://nodequery.com/) — Free basic server monitors up to 10 servers
  * [circonus.com](https://www.circonus.com/) — Free for 20 metrics
  * [uptimerobot.com](https://uptimerobot.com/) — Website monitoring, 50 monitors free
  * [sitemonki.com](https://sitemonki.com/) — Website, domain, Cron & SSL monitoring, 5 monitors in each category for free
  * [statuscake.com](https://www.statuscake.com/) — Website monitoring, unlimited tests free with limitations
  * [bmc.com](https://www.bmc.com/truesightpulse/) — Free 1 second resolution for up to 10 servers
  * [ghostinspector.com](https://ghostinspector.com/) — Free website and web application monitoring. Single user, 100 test runs/month
  * [sematext.com](https://sematext.com/) — Free for 24 hours metrics, unlimited number of servers, 10 custom metrics, 500,000 custom metrics data points, unlimited dashboards, users, etc.
  * [stathat.com](https://www.stathat.com/) — Get started with 10 stats for free, no expiration
  * [skylight.io](https://www.skylight.io/) — Free for first 100,000 requests (Rails only)
  * [appdynamics.com](https://www.appdynamics.com/) — Free for 24 hours metrics, application performance management agents limited to one Java, one .NET, one PHP and one Node.js
  * [deadmanssnitch.com](https://deadmanssnitch.com/) — Monitoring for cron jobs. 1 free snitch (monitor), more if you refer others to sign up
  * [freeboard.io](https://freeboard.io/) — Free for public projects. Dashboards for your Internet of Things (IoT) projects
  * [loader.io](https://loader.io/) — Free load testing tools with limitations
  * [speedchecker.xyz](https://probeapi.speedchecker.xyz/) — Performance Monitoring API, checks Ping, DNS, etc.
  * [blackfire.io](https://blackfire.io/) — Blackfire is the SaaS-delivered Application Performance Solution. Free Hacker plan (PHP only)
  * [apimetrics.io](https://apimetrics.io/) — Automated API Performance Monitoring, Testing and Analytics. Free Plan, manually make API calls and Run from their West Coast servers
  * [healthchecks.io](https://healthchecks.io) — Monitor your cron jobs and background tasks. Free for up to 20 checks.
  * [assertible.com](https://assertible.com) — Automated API testing and monitoring. Free plans for teams and individuals.
  * [opsgenie.com](https://www.opsgenie.com/) — Powerful alerting and on-call management for operating always-on services. Free up to 5 users.
  * [paessler.com](https://www.paessler.com/) — Powerful infrastructure and network monitoring solution including alerting, strong visualization capabilities and basic reporting. Free up to 100 sensors.
  * [pingbreak.com](https://pingbreak.com/) — Modern uptime monitoring service. Check unlimited URLs and get downtime notifications via Discord, Slack or email.
  * [pagertree.com](https://pagertree.com/) - Simple interface for alerting and on-call management. Free up to 5 users.

## Crash and Exception Handling

  * [rollbar.com](https://rollbar.com/) — Exception and error monitoring, free plan with 5,000 errors/month, unlimited users, 30 days retention
  * [bugsnag.com](https://www.bugsnag.com/) — Free for up to 2,000 errors/month after the initial trial
  * [sentry.io](https://sentry.io/) — Sentry tracks app exceptions in real-time, has a small free plan. Free for 5k errors per month/ 1 user, unrestricted use if self-hosted
  * [honeybadger.io](https://www.honeybadger.io) - Exception, uptime, and cron monitoring that's so awesome, you'll wish your site had more errors. Honeybadger is free for solo devs and open-source projects (12,000 errors/month).

## Search

  * [algolia.com](https://www.algolia.com/) — Hosted search-as-you-type (instant). Free hacker plan up to 10,000 documents and 100,000 operations. Bigger free plans available for community/Open Source projects
  * [bonsai.io](https://bonsai.io/) — Free 1 GB memory and 1 GB storage
  * [searchly.com](http://www.searchly.com/) — Free 2 indices and 5 MB storage

## Email

  * [Contact.do](https://contact.do/) — Contact form in a link (bitly for contact forms) - totally free!
  * [mailinator.com](https://www.mailinator.com/) — Free, public, email system where you can use any inbox you want
  * [cloudmersive.com](https://www.cloudmersive.com/email-verification-api) — Email validation and verification API for developers, 2,000 free API requests/month
  * [sparkpost.com](https://www.sparkpost.com/) — First 500 emails/month free
  * [mailgun.com](https://www.mailgun.com/) — First 10,000 emails and 100 e-mail address validation is free each month
  * [tinyletter.com](https://tinyletter.com/) — 5,000 subscribers/month free
  * [mailchimp.com](https://mailchimp.com/) — 2,000 subscribers and 12,000 emails/month free
  * [sendgrid.com](https://sendgrid.com/) — 100 emails/day and 2,000 contacts free
  * [phplist.com](https://phplist.com/) — Hosted version allow 300 emails/month free
  * [MailerLite.com](https://www.mailerlite.com) — 1,000 subscribers/month, unlimited email free
  * [mailjet.com](https://www.mailjet.com/) — 6,000 emails/month free
  * [sendinblue.com](https://www.sendinblue.com/) — 9,000 emails/month free
  * [mailtrap.io](https://mailtrap.io/) — Fake SMTP server for development, free plan with 1 inbox, 50 messages, no team member, 2 emails/second, no forward rules
  * [zoho.com](https://www.zoho.com/mail/) — Free Webmail and collaboration for up to 5 users
  * [Yandex.Connect](https://connect.yandex.com/pdd/) — Free email and DNS hosting for up to 1,000 users
  * [moosend.com](https://moosend.com/) — Mailing list management service. Free account for 6 months for startups
  * [debugmail.io](https://debugmail.io/) — Easy to use testing mail server for developers
  * [mailboxlayer.com](https://mailboxlayer.com/) — Email validation and verification JSON API for developers. 1,000 free API requests/month
  * [mailcatcher.me](https://mailcatcher.me/) — Catches mail and serves it through a web interface
  * [yopmail.fr](http://www.yopmail.fr/en/) — Disposable email addresses
  * [kickbox.io](https://kickbox.io/) — Verify 100 emails free, real-time API available
  * [inumbo.com](http://inumbo.com/) — SMTP based spam filter, free for 10 users
  * [biz.mail.ru](https://biz.mail.ru/) — 5,000 mailboxes with 25 GB each per custom domain with DNS hosting
  * [sendpulse.com](https://sendpulse.com) — 50 emails free/hour, first 12,000 emails/month free
  * [pepipost.com](https://pepipost.com) — 30k emails free for first month, then first 100 emails/day free
  * [elasticemail.com](https://elasticemail.com) — 100 free emails/day. 1,000 emails for $0.09 through API (pay as you go).
  * [mail-tester.com](https://www.mail-tester.com) — Test if email's dns/spf/dkim/dmarc settings are correct, 20 free/month
  * [migadu.com](https://www.migadu.com/) — Email Hosting (Webmail, SMTP, IMAP, ...) — free plan is limited to 10 outgoing mails/day
  * [socketlabs.com](https://www.socketlabs.com) - 40k emails free for first month, then first 2000 emails/month free
  * [postmarkapp.com](https://postmarkapp.com/) - 100 emails/month free, unlimited DMARC weekly digests
  * [testmail.app](https://testmail.app/) - Automate end-to-end email tests with unlimited mailboxes and a GraphQL API. 100 emails/month free forever, unlimited free for open source.
  * [trashmail.com](https://www.trashmail.com) - Free disposable email addresses with forwarding and automatic address expiration
  * [Sender](https://www.sender.net) Up to 15 000 emails/month - Up to 2 500 subscribers
  * [Buttondown](https://buttondown.email/) — Newsletter service. Up to 1,000 subscribers free
  * [Substack](https://substack.com) — Unlimited free newsletter service. Start paying when you charge for it.
  * [10minutemail](https://10minutemail.com) - Free, temporary email for testing.
  * [Mailnesia](https://mailnesia.com) - Free temporary/disposable email, which auto visit registration link.
  * [ImprovMX](https://improvmx.com) – Free email forwarding
  * [Burnermail](https://burnermail.io/) – Free 5 Burner Email Addresses, 1 Mailbox, 7 day Mailbox History
  * [mailkitchen](https://www.mailkitchen.com/) — Free for life without commitment, 10,000 emails/month, 1,000 emails/day
  * [AnonAddy](https://anonaddy.com) - Open-source anonymous email forwarding, create unlimited email aliases for free

## Forms
  * [Formspree.io](https://formspree.io/) — Send email using an HTTP POST request. Free tier limits to 1000 submissions per month and must expose email address in the API call.
  * [Typeform.com](https://www.typeform.com/) — Include beautifully designed forms on websites.  Free plan allows only 10 fields per form and 100 responses per month.
  * [Formcarry.com](https://formcarry.com) - HTTP POST Form endpoint, Free plan allows 100 submissions per month.
  * [formaholic.com](https://formaholic.com) — Simple form endpoint. Perfect for static sites.
  * [formlets.com](https://formlets.com/) — Online forms, unlimited single page forms/month, 100 submissions/month, email notifications.
  * [getform.io](https://getform.io/) - Form backend platform for designers and developers, 1 form, 100 submissions, Single file upload, 100MB file storage.
  * [99inbound.com](https://www.99inbound.com/) - Build forms and share them online. Get an email or Slack message for each submission. Free plan has 2 forms, 100 entries per month, basic email & Slack.
  * [formingo.co](https://www.formingo.co/)- Easy HTML forms for static websites, get started for free without registering an account. Free plan allows 500 submissions per month, customizable reply-to email address.
  * [formspark.io](https://formspark.io/) -  Form to Email service, free plan allows unlimited forms, 500 submissions per month, support by Customer assistance team.
  * [smartforms.dev](https://smartforms.dev/) - Powerful and easy form backend for your website, forever free plan allows 50 submissions per month, 100MB file storage, Zapier integration, CSV/JSON export, custom redirect, custom response page, Telegram & Slack bot, single email notifications.

## CDN and Protection

  * [PageCDN.com](https://pagecdn.com/) - Offers free Public CDN for everyone, and free Private CDN for opensource / nonprofits.
  * [cloudflare.com](https://www.cloudflare.com/) — Basic service is free, good for a blog, it also offers a free SSL certificate service and 5 firewall rules.
  * [bootstrapcdn.com](https://www.bootstrapcdn.com/) — CDN for bootstrap, bootswatch and fontawesome.io
  * [cdnjs.com](https://cdnjs.com/) — CDN for JavaScript libraries, CSS libraries, SWF, images, etc.
  * [jsdelivr.com](https://www.jsdelivr.com/) — CDN of OSS (JS, CSS, fonts) for developers and webmasters, accepts PRs to add more
  * [raw.githack.com](https://raw.githack.com/) — A modern replacement of **rawgit.com** which simply hosts file using Cloudflare
  * [developers.google.com](https://developers.google.com/speed/libraries/) — The Google Hosted Libraries is a content distribution network for the most popular, Open Source JavaScript libraries
  * [Microsoft Ajax](https://docs.microsoft.com/en-us/aspnet/ajax/cdn/overview) — The Microsoft Ajax CDN hosts popular third-party JavaScript libraries such as jQuery and enables you to easily add them to your Web application
  * [toranproxy.com](https://toranproxy.com/) — Proxy for Packagist and GitHub. Never fail CD. Free for personal use, 1 developer, no support
  * [Web Support Revolution](https://w.tools/) — Free CDN, backup, firewall, antivirus and monitoring.
  * [section.io](https://www.section.io/) — A simple way to spin up and manage a complete Varnish Cache solution. Supposedly free forever for one site
  * [netdepot.com](https://www.netdepot.com/cdn/) — First 100 GB free/month
  * [speeder.io](https://speeder.io/) — Uses KeyCDN. Automatic image optimization and free CDN boost. Free and does not require any server changes
  * [jare.io](http://www.jare.io) — CDN for images. Uses AWS CloudFront
  * [unpkg.com](https://unpkg.com/) — CDN for everything on npm
  * [staticaly.com](https://staticaly.com/) — CDN for Git repos (GitHub, GitLab, Bitbucket), WordPress-related assets and images
  * [ddos-guard.net](https://ddos-guard.net/store/web) — Free CDN, DDoS protection and SSL certificate
  * [ovh.ie](https://www.ovh.ie/ssl-gateway/) — Free DDos protection and SSL certificate

## PaaS

  * [engineyard.com](https://www.engineyard.com/) — Engine Yard provides 500 free hours
  * [appharbor.com](https://appharbor.com/) — A .Net PaaS that provides 1 free worker
  * [heroku.com](https://www.heroku.com/) — Host your apps in the cloud, free for single process apps
  * [firebase.google.com](https://firebase.google.com) — Build real-time apps, the free plan has 100 max connections, 10 GB data transfer, 1 GB data storage, 1 GB hosting storage and 10 GB hosting transfer
  * [outsystems.com](https://www.outsystems.com/) — Enterprise web development PaaS for on-premise or cloud, free "personal environment" offering allows for unlimited code and up to 1 GB database
  * [scn.sap.com](https://scn.sap.com/docs/DOC-56411) — The in-memory Platform-as-a-Service offering from SAP. Free developer accounts come with 1 GB structured, 1 GB unstructured, 1 GB of Git data and allow you to run HTML5, Java and HANA XS apps
  * [mendix.com](https://www.mendix.com/) — Rapid Application Development for Enterprises, unlimited number of free sandbox environments supporting 10 users, 100 MB of files and 100 MB database storage each
  * [pythonanywhere.com](https://www.pythonanywhere.com/) — Cloud Python app hosting. Beginner account is free, 1 Python web application at your-username.pythonanywhere.com domain, 512 MB private file storage, one MySQL database
  * [configure.it](https://www.configure.it/) — Mobile app development platform, free for 2 projects, limited features but no resource limits
  * [zeit.co/now](https://zeit.co/now) — Serverless platform with support for multiple languages (including static sites) and single command deployment. Free tier includes SSL, 20GB bandwidth, 100 deployments.
  * [sandstorm.io](https://sandstorm.io/) — Sandstorm is an open source operating system for personal and private clouds. Free plan offers 200 MB storage and 5 grains free
  * [gearhost.com](https://www.gearhost.com/pricing) — Platform for .NET and PHP apps. 256 MB of RAM for free on a shared server with limited resources
  * [glitch.com](https://glitch.com/) — Free unlimited public/private hosting with features such as code sharing and real-time collaboration
  * [gigalixir.com](https://gigalixir.com/) - Gigalixir provide 1 free instance that never sleeps, and free-tier PostgreSQL database limited to 2 connections, 10, 000 rows and no backups, for Elixir/Phoenix apps.
  * [workers.dev](https://workers.dev) - Deploy serverless code for free on Cloudflare's global network. 100,000 free requests per day with a workers.dev subdomain.
  * [pipedream.com](https://pipedream.com) - An integration platform built for developers. Develop any workflow, based on any trigger. Workflows are code, which you can run [for free](https://docs.pipedream.com/pricing/). No server or cloud resources to manage.
  * [okteto.com](https://okteto.com) - Managed Kubernetes service designed for developers. Free developer accounts come with five namespaces, each with 8GB of RAM and 4 CPUs.
  * [kubesail.com](https://kubesail.com) - Managed Kubernetes namespace service designed for developers. Free developer accounts come with with 1 Core of CPU, 512MB of RAM, 100MB of storage and 1 domain.

## BaaS

  * [back4app.com](https://www.back4app.com) - Back4App is an easy-to-use, flexible and scalable backend based on Parse Platform.
  * [blockspring.com](https://www.blockspring.com/) — Cloud functions. Free for 5 million runs/month
  * [progress.com](https://www.progress.com/kinvey) — Mobile backend, starter plan has unlimited requests/second, with 1 GB of data storage. Enterprise application support
  * [backendless.com](https://backendless.com/) — Mobile and Web Baas, with 1 GB file storage free, push notifications 50000/month, and 1000 data objects in table.
  * [hasura.io](https://hasura.io/) — Platform to build and deploy app backends fast, free for single node cluster.
  * [pusher.com](https://pusher.com/beams) — Free, unlimited push notifications for 2000 monthly active users. A single API for iOS and Android devices.
  * [quickblox.com](https://quickblox.com/) — A communication backend for instant messaging, video and voice calling and push notifications
  * [pushbots.com](https://pushbots.com/) — Push notification service. Free for up to 1.5 million pushes/month
  * [onesignal.com](https://onesignal.com/) — Unlimited free push notifications
  * [getstream.io](https://getstream.io/) — Build scalable news feeds and activity streams in a few hours instead of weeks, free for 3 million feed updates/month
  * [tyk.io](https://tyk.io/) — API management with authentication, quotas, monitoring and analytics. Free cloud offering
  * [iron.io](https://www.iron.io/) — Async task processing (like AWS Lambda) with free tier and 1-month free trial
  * [nstack.com](https://nstack.com/) — Async task processing (like AWS Lambda). 10 free private services and unlimited free public services
  * [pubnub.com](https://www.pubnub.com/) — Free push notifications for up to 1 million messages/month and 100 active daily devices
  * [pushtechnology.com](https://www.pushtechnology.com/) — Real-time Messaging for browsers, smartphones and everyone. 100 concurrent connections. Free 10 GB data/month
  * [zapier.com](https://zapier.com/) — Connect the apps you use, to automate tasks. 5 zaps, every 15 minutes and 100 tasks/month
  * [stackstorm.com](https://stackstorm.com/) — Event-driven automation for apps, services and workflows, free without flow, access control, LDAP,...
  * [simperium.com](https://simperium.com/) — Move data everywhere instantly and automatically, multi-platform, unlimited sending and storage of structured data, max. 2,500 users/month
  * [pushcrew.com](https://pushcrew.com/) — Push notification service. Unlimited notifications up to 2000 Subscribers
  * [streamdata.io](https://streamdata.io/) — Turns any REST API into an event-driven streaming API. Free plan up to 1 million messages and 10 concurrent connections
  * [posthook.io](https://posthook.io/) — Job Scheduling Service. Allows you to schedule requests for specific times. 500 scheduled requests/month free.
  * [paraio.com](https://paraio.com) — Backend service API with flexible authentication, full-text search and caching. Free for 1 app, 1GB app data.
  * [remotemysql.com](https://remotemysql.com) — Remote MySQL Database hosting, setup is instant and use phpMyAdmin for administration, free for 100Mb data, free backups, no query limits and 99% uptime.
  * [ably.com](https://www.ably.com) - APIs for realtime messaging, push notifications, and event-driven API creation. Free plan has 3m messages/mo, 100 concurrent connections, 100 concurrent channels.
  * [netlicensing.io](https://netlicensing.io) - A cost-effective and integrated Licensing-as-a-Service (LaaS) solution for your software on any platform from Desktop to IoT and SaaS. Basic Plan for *FREE* while you are a student.

## Web Hosting

  * [pages.github.com](https://pages.github.com/) — Hosting static site directly from GitHub repository
  * [gitlab.com](https://about.gitlab.com/product/pages/) — Hosting static site directly from GitLab repository
  * [sourceforge.net](https://sourceforge.net/) — Find, Create and Publish Open Source software for free
  * [devport.co](http://devport.co/) — Turn GitHub projects, apps and websites into a personal developer portfolio
  * [netlify.com](https://www.netlify.com/) — Builds, deploy and hosts static site or app, free for 100 GB data and 100 GB/month bandwidth
  * [sanity.io](https://www.sanity.io/) – Hosted backend for structured content with customizable MIT licensed editor built with React. Unlimited projects. 3 users, 2 datasets, 500k API CDN requests, 5GB assets for free per project
  * [pantheon.io](https://pantheon.io/) — Drupal and WordPress hosting, automated DevOps and scalable infrastructure. Free for developers and agencies
  * [acquia.com](https://www.acquia.com/) — Hosting for Drupal sites. Free tier for developers. Free development tools (such as Acquia Dev Desktop) also available
  * [readthedocs.org](https://readthedocs.org/) — Free documentation hosting with versioning, PDF generation and more
  * [bubble.is](https://bubble.is/) — Visual programming to build web and mobile apps without code, free 100 visitors/month, 2 apps
  * [contentful.com](https://www.contentful.com/) — Headless CMS. Content management and delivery APIs in the cloud. Comes with one free micro space that includes 10 users, 5000 records, 24 Content Types, 2 locales.
  * [tilda.cc](https://tilda.cc/) — One site, 50 pages, 50 MB storage, only the main pre-defined blocks among 170+ available, no fonts, no favicon and no custom domain
  * [surge.sh](https://surge.sh/) — Static web publishing for Front-End developers. Unlimited sites with custom domain support
  * [neocities.org](https://neocities.org) — Static, 1 GB free storage with 200 GB Bandwidth.
  * [txti.es](http://txti.es/) — Quickly create web pages with markdown.
  * [kuber.host](https://kuber.host/) — Kubernetes hosting with free plan
  * [cloudno.de](https://cloudno.de/) — Free cloud hosting for Node.js apps.
  * [heliohost.org](https://www.heliohost.org) — Community powered free hosting for everyone.
  * [render.com](https://render.com) — A unified platform to build and run all your apps and web app free SSL, a global CDN, private networks and auto deploys from Git, free for static web page.
  * [000WebHost](https://www.000webhost.com/) — Zero cost website hosting with PHP, MySQL, cPanel & no ads!
  * [Free Hosting](http://freehostingnoads.net/) — Free Hosting With PHP 5, Perl, CGI, MySQL, FTP, File Manager, POP E-Mail, free sub-domains, free domain hosting, DNS Zone Editor, Web Site Statistics, FREE Online Support and many more features not offered by other free hosts.
  * [Awardspace.com](https://www.awardspace.com) — Free web hosting + a free short domain, PHP, MySQL, App Installer, Email Sending & No Ads.
  * [Freehostia](https://www.freehostia.com) — FreeHostia offers free hosting services incl. an industry-best Control Panel & a 1-click installation of 50+ free apps. Instant setup. No forced ads.
  * [Byet](https://byet.host) — Byet provides you with a massive free, and ad-free load balanced free web hosting service including PHP, MySQL, FTP, Vistapanel & more!..
  * [Versoly](https://versoly.com/) — SaaS focussed website builder - unlimited websites, 70+ blocks, 5 templates, custom CSS, favicon, SEO and forms. No custom domain.

## DNS

  * [freedns.afraid.org](https://freedns.afraid.org/) — Free DNS hosting
  * [dns.he.net](https://dns.he.net/) — Free DNS hosting service with Dynamic DNS Support
  * [luadns.com](https://www.luadns.com/) — Free DNS hosting, 3 domains, all features with reasonable limits
  * [Yandex.Connect](https://connect.yandex.com/pdd/) — Free email and DNS hosting for up to 1,000 users
  * [selectel.com](https://selectel.com/services/dns/) — Free DNS hosting, anycast, 10 geo zones
  * [cloudns.net](https://www.cloudns.net/) — Free DNS hosting up to 1 domain with 50 records
  * [ns1.com](https://ns1.com/) — Data Driven DNS, automatic traffic management, 500k free queries
  * [zonewatcher.com](https://zonewatcher.com) — Automatic backups and DNS change monitoring. 1 domain free
  * [namecheap.com](https://www.namecheap.com/domains/freedns/) — Free DNS. No limit on number of domains
  * [dynu.com](https://www.dynu.com/) — Free dynamic DNS service
  * [noip](https://www.noip.com/) — a dynamic dns service that allows up to 3 hostnames free with confirmation every 30 days
  * [freenom.com](https://freenom.com/) — Free domain provider. Get FQDN for free.
  * [duckdns.org](https://www.duckdns.org/) — Free DDNS with up to 5 domains on the free tier. With configuration guides for various setups.
  * [1984.is](https://www.1984.is/product/freedns/) — Free DNS service with API, and lots of other free DNS features included.
  * [Cloudflare](https://www.cloudflare.com/) - Free DNS.  Unlimited number of domains.
  * [biz.mail.ru](https://biz.mail.ru) — Free email and DNS hosting for up to 5,000 users
  * [pointhq.com](https://pointhq.com/developer) — Free DNS hosting on Heroku.
  * [dnspod.com](https://www.dnspod.com/) — Free DNS hosting.
  * [web.gratisdns.dk](https://web.gratisdns.dk/domaener/dns/) — Free DNS hosting.
  * [zoneedit.com](https://www.zoneedit.com/free-dns/) — Free DNS hosting with Dynamic DNS Support.
  * [zilore.com](https://zilore.com/ru/dns) — Free DNS hosting.

## IaaS

  * [backblaze.com](https://www.backblaze.com/b2/) — Backblaze B2 cloud storage. Free 10 GB (Amazon S3-like) object storage for unlimited time
  * [www.terraform.io](https://www.terraform.io/) — Terraform Cloud. Free remote state management and team collaboration for teams up to 5 users.
  * [scaleway.com](https://www.scaleway.com/en/object-storage/) — S3-Compatible Object Storage. Free 75 GB storage and external outgoing traffic

## DBaaS

   * [redislabs.com](https://redislabs.com/redis-cloud) — Redis as a Service, 30 MB and 30 concurrent connections free
   * [redsmin.com](https://www.redsmin.com/) — Online real-time monitoring and administration service for Redis, 1 Redis instance free
   * [elephantsql.com](https://www.elephantsql.com/) — PostgreSQL as a service, 20 MB free
   * [heroku.com](https://www.heroku.com/) — PostgreSQL as a service, up to 10,000 rows and 20 connections free (provided as an "addon," but can be attached to an otherwise empty app and accessed externally)
   * [graphenedb.com](https://www.graphenedb.com/) — Neo4j as a service, up to 1,000 nodes and 10,000 relations free
   * [MongoDB Atlas](https://www.mongodb.com/cloud/atlas) — free tier gives 512 MB
   * [scalingo.com](https://scalingo.com/) — Primarily a PaaS but offers a 128MB to 192MB free tier of MySQL, PostgreSQL or MongoDB
   * [skyvia.com](https://skyvia.com/) — Cloud Data Platform, offers free tier and all plans are completely free while in beta
   * [airtable.com](https://airtable.com/) — Looks like a spreadsheet, but it's a relational database, unlimited bases, 1,200 rows/base and 1,000 API requests/month
   * [FaunaDB](https://fauna.com/) — Serverless cloud database, with native GraphQL, multi-model access and daily free tiers up to 5GB

## STUN, WebRTC, Web Socket Servers and Other Routers

   * [conveyor.cloud](https://conveyor.cloud/) — Visual Studio extension to expose IIS Express to the local network or over a tunnel to a public URL.
   * [scaledrone.com](https://www.scaledrone.com/) — Push messaging service. Free for up to 20 simultaneous connections and 100,000 messages/day
   * [stun:stun.l.google.com:19302](stun:stun.l.google.com:19302) — Google STUN
   * [stun:global.stun.twilio.com:3478?transport=udp](stun:global.stun.twilio.com:3478?transport=udp) — Twilio STUN
   * [segment.com](https://segment.com/) — Hub to translate and route events to other third-party services. 100,000 events/month free
   * [ngrok.com](https://ngrok.com/) — Expose locally running servers over a tunnel to a public URL.
   * [serveo.net](https://serveo.net/) — Quickly expose any local port to the public internet on a servo subdomain using an SSH tunnel, includes SSH GUI to replay requests over HTTP.
   * [ZeroTier](https://www.zerotier.com) — FOSS managed virtual Ethernet as a service. Unlimited end-to-end encrypted networks of 100 clients on free plan. Clients for desktop/mobile/NA; web interface for configuration of custom routing rules and approval of new client nodes on private networks.
   * [Hamachi](https://www.vpn.net/) — LogMeIn Hamachi is a hosted VPN service that lets you securely extend LAN-like networks to distributed teams with free plan allows unlimited networks with up to 5 peoples
   * [webhookrelay.com](https://webhookrelay.com) — Manage, debug, fan-out and proxy all your webhooks to public or internal (ie: localhost) destinations. Also, expose servers running in a private network over a tunnel by getting a public HTTP endpoint (`https://yoursubdomain.webrelay.io <----> http://localhost:8080`).

## Issue Tracking and Project Management

   * [todoist.com](https://todoist.com/) — Collaborative and individual task management. Free, Premium and Team plans are available. Discounts provided for eligible users.
   * [bitrix24.com](https://www.bitrix24.com/) — Free intranet and project management tool
   * [pivotaltracker.com](https://www.pivotaltracker.com/) — Free for unlimited public projects and two private projects with 3 total active users (read-write) and unlimited passive users (read-only).
   * [kanbantool.com](https://kanbantool.com/) — Kanban board-based project management. Free, paid plans with more options
   * [kanrails.com](https://kanrails.com/) — Kanban board-based project management. Free for 3 collaborators, 2 projects and 5 tracks. Paid plans available for unlimited collaborators, projects and tracks.
   * [kanbanflow.com](https://kanbanflow.com/) — Board-based project management. Free, premium version with more options
   * [zenhub.io](https://www.zenhub.io/) — The only project management solution inside GitHub. Free for public repos, OSS and nonprofit organizations
   * [trello.com](https://trello.com/) — Board-based project management. Unlimited Personal Boards, 10 Team Boards.
   * [clickup.com](https://clickup.com/) — Project management. Free, premium version with cloud storage. Mobile applications and Git integrations available
   * [LeanBoard](https://www.leanboard.io) — Collaborative whiteboard with sticky notes for your GitHub issues (Useful for Example Mapping and other techniques)
   * [huboard.com](https://huboard.com/) — Instant project management for your GitHub issues, free for Open Source
   * [taiga.io](https://taiga.io/) — Project management platform for startups and agile developers, free for Open Source
   * [YouTrack](https://www.jetbrains.com/youtrack/buy/#edition=incloud) — Free hosted YouTrack (InCloud) for FOSS projects, private projects (free for 3 users). Includes time tracking and agile boards
   * [github.com](https://github.com/) — In addition to its Git storage facility, GitHub offers basic issue tracking
   * [asana.com](https://asana.com/) — Free for private project with collaborators
   * [acunote.com](https://www.acunote.com/) — Free project management and SCRUM software for up to 5 team members
   * [gliffy.com](https://www.gliffy.com/) — Online diagrams: flowchart, UML, wireframe,... Also plugins for Jira and Confluence. 5 diagrams and 2 MB free
   * [cacoo.com](https://cacoo.com/) — Online diagrams in real-time: flowchart, UML, network. Free max. 15 users/diagram, 25 sheets
   * [draw.io](https://www.draw.io/) — Online diagrams stored locally, in Google Drive, OneDrive or Dropbox. Free for all features and storage levels
   * [Cloudcraft](https://cloudcraft.co/) — Design a professional architecture diagram in minutes with the Cloudcraft visual designer, optimized for AWS with smart components that show live data too.
   * [Azure DevOps](https://azure.microsoft.com/services/devops/) — Unlimited free private code repositories; Tracks bugs, work items, feedback and more
   * [testlio.com](https://testlio.com/) — Issue tracking, test management and beta testing platform. Free for private use
   * [vivifyscrum.com](https://www.vivifyscrum.com/) — Free tool for Agile project management. Scrum Compatible
   * [targetprocess.com](https://www.targetprocess.com/) — Visual project management, from Kanban and Scrum to almost any operational process. Free for unlimited users, up to 1,000 data entities {[more details](https://www.targetprocess.com/pricing/)}
   * [taskulu.com](https://taskulu.com/) — Role based project management. Free up to 5 users. Integration with GitHub/Trello/Dropbox/Google Drive
   * [contriber.com](https://www.contriber.com/) — Customizable project management platform, free starter plan, 5 workspaces
   * [planitpoker.com](https://www.planitpoker.com/) — Free online planning poker (estimation tool)
   * [ubertesters.com](https://ubertesters.com/) — Test platform, integration and crowdtesters, 2 projects, 5 members
   * [plan.io](https://plan.io/) — Project Management with Repository Hosting and more options. Free for 2 users with 10 customers and 500MB Storage
   * [taskade.com](https://www.taskade.com/) — Real-time collaborative task lists and outlines for teams
   * [zenkit.com](https://zenkit.com) — Project management and collaboration tool. Free for up to 5 members, 5 GB attachments.
   * [Instabug](https://instabug.com) —  A comprehensive bug reporting and in-app feedback SDK for mobile apps. Free plan up to 1 app and 1 member.
   * [Office 365 Developer](https://developer.microsoft.com/en-us/office/dev-program) — Free one-year Office 365 E3 subscription for development/testing.
   * [senseitool.com](https://www.senseitool.com/) — An agile retrospective tool - Free.
   * [Gitlab](https://gitlab.com) - Offers basic issue tracking for projects.
   * [Clubhouse](https://clubhouse.io/) - Project management platform. Free for up to 10 users forever
   * [Ora](https://ora.pm/) - Agile task management & team collaboration. Free for up to 3 users and files are limited to 10 MB.
   * [Tadum](https://tadum.app) - Meeting agenda and minutes app designed for recurring meetings, free for teams up to 10
   * [Basecamp](https://basecamp.com/personal) - To-do lists, milestone management, forum-like messaging, file sharing, and time tracking. Up to 3 projects, 20 users, and 1GB of storage space.
   * [GraphQL Inspector](https://github.com/marketplace/graphql-inspector) - GraphQL Inspector ouputs a list of changes between two GraphQL schemas. Every change is precisely explained and marked as breaking, non-breaking or dangerous.

## Storage and Media Processing

   * [redbooth.com](https://redbooth.com) — P2P file syncing, free for up to 2 users
   * [cloudinary.com](https://cloudinary.com/) — Image upload, powerful manipulations, storage and delivery for sites and apps, with libraries for Ruby, Python, Java, PHP, Objective-C and more. Perpetual free tier includes 7,500 images/month, 2 GB storage, 5 GB bandwidth
   * [easyDB.io](https://easydb.io/) — one-click, hosted database provider. They provide a database for the programming language of your choice for development purposes. The DB is ephemeral and will be deleted after 24 or 72 hours on the free tier.
   * [piio.co](https://piio.co/) — Responsive image optimization and delivery for every website. Free plan for developers and personal websites. Includes free CDN, WebP and Lazy Loading out of the box.
   * [gumlet.com](https://www.gumlet.com/) — Image resize-as-a-service. It also optimizes images and performs delivery via CDN. Free tier includes 1 GB bandwidth and unlimited number of image processing every month for 1 year.
   * [plot.ly](https://plot.ly/) — Graph and share your data. Free tier includes unlimited public files and 10 private files
   * [transloadit.com](https://transloadit.com/) — Handles file uploads and encoding of video, audio, images, documents. Free for Open source, charities, and students via the GitHub Student Developer Pack. Commercial applications get 2 GB free for test driving
   * [podio.com](https://podio.com/) — You can use Podio with a team of up to five people and try out the features of the Basic Plan, except user management
   * [shrinkray.io](https://shrinkray.io/) — Free image optimization of GitHub repos
   * [kraken.io](https://kraken.io/) — Image optimization for website performance as a service, free plan up to 1 MB file size
   * [placeholder.com](https://placeholder.com/) — A quick and simple image placeholder service
   * [placekitten.com](https://placekitten.com/) — A quick and simple service for getting pictures of kittens for use as placeholders
   * [embed.ly](https://embed.ly/) — Provides APIs for embedding media in a webpage, responsive image scaling, extracting elements from a webpage. Free for up to 5,000 URLs/month at 15 requests/second
   * [otixo.com](https://www.otixo.com/) — Encrypt, share, copy and move all your cloud storage files from one place. Basic plan provides unlimited files transfer with 250 MB max. file size and allows 5 encrypted files
   * [tinypng.com](https://tinypng.com/) — API to compress and resize PNG and JPEG images, offers 500 compressions for free each month
   * [filestack.com](https://www.filestack.com/) — File picker, transform and deliver, free for 250 files, 500 transformations and 3 GB bandwidth
   * [packagecloud.io](https://packagecloud.io/) — Hosted Package Repositories for YUM, APT, RubyGem and PyPI.  Limited free plans, open source plans available via request
   * [image-charts.com](https://www.image-charts.com/) — Unlimited image chart generation with a watermark
   * [jsonbin.io](https://jsonbin.io/) — Free JSON data storage service, ideal for small-scale web apps, website, mobile apps.
   * [jsonstore.io](https://www.jsonstore.io/) — One click JSON storage endpoint
   * [npoint.io](https://www.npoint.io/) — JSON store with collaborative schema editing
   * [QuickChart](https://quickchart.io) — Generate embeddable image charts, graphs, and QR codes

## Design and UI

  * [landen.co](https://www.landen.co) — Generate, edit and publish beautiful websites and landing pages for your startup. All without code. Free tier allows you to have one website, fully customizable and published on the web.
  * [pixlr.com](https://pixlr.com/) — Free online browser editor on the level of commercial ones.
  * [imagebin.ca](https://imagebin.ca/) — Pastebin for images.
  * [cloudconvert.com](https://cloudconvert.com/) — Convert anything to anything. 208 supported formats including videos to gif.
  * [resizeappicon.com](https://resizeappicon.com/) — A simple service to resize and manage your app icons.
  * [vectr.com](https://vectr.com/) — Free Design App for Web + Desktop.
  * [clevebrush.com](https://www.cleverbrush.com/) — Free Graphics Design / Photo Collage App, also they offer paid integration of it as component.
  * [walkme.com](https://www.walkme.com/) — Enterprise Class Guidance and Engagement Platform, free plan 3 walk-thrus up to 5 steps/walk.
  * [marvelapp.com](https://marvelapp.com/) — Design, prototyping and collaboration, free plan limited to one user and one project.
  * [Zeplin](https://zeplin.io/) — Designer and developer collaboration platform. Show designs, assets and styleguides. Free for 1 project.
  * [figma.com](https://www.figma.com) — Online, collaborative design tool for teams; free tier includes unlimited files and viewers with a max of 2 editors and 3 projects.
  * [designer.io](https://www.designer.io/) — Design tool for UI, illustrations and more. Has a native app. Free.
  * [photopea.com](https://www.photopea.com) — A Free, Advanced online design editor with Adobe Photoshop UI supporting PSD, XCF & Sketch formats (Adobe Photoshop, Gimp and Sketch App).
  * [pexels.com](https://www.pexels.com/) - Free stock photos for commercial use. Has free API that allows you to search photos by keywords.
  * [unsplash.com](https://unsplash.com/) - Free stock photos for commercial and noncommercial purposes (do-whatever-you-want license).
  * [whimsical.com](https://whimsical.com/) - Collaborative flowcharts, wireframes, sticky notes and mind maps. Create up to 4 free boards.
  * [Mindmup.com](https://www.mindmup.com/) — Unlimited mind maps for free, and store them in the cloud. Your mind maps are available everywhere, instantly, from any device. 
  * [lensdump.com](https://lensdump.com/) - Free cloud image hosting.
  * [Adobe XD](https://www.adobe.com/products/xd.html) - Wireframe & Prototyping tool similar to Sketch. Free plan covers: 1 active shared design spec, Adobe Fonts Free (limited set of fonts), 2GB of cloud storage.
  * [AllTheFreeStock](https://allthefreestock.com) - a curated list of free stock images, audio and videos.
  * [CodeMyUI](https://codemyui.com) - Handpicked collection of Web Design & UI Inspiration with Code Snippets.
  * [Pencil](https://github.com/evolus/pencil) - Open source design tool using Electron.
  * [Invision App](https://www.invisionapp.com) - UI design and prototyping tool. Desktop and webapp available. Free to use with 1 active prototype.
  * [Proto.io](https://www.proto.io) - Create fully interactive UI prototypes without coding. Free tier available when free trial ends. Free tier includes: 1 user, 1 project, 5 prototypes, 100MB online storage and preview in proto.io app.

## Data Visualization on Maps

   * [opencagedata.com](https://opencagedata.com) — Geocoding API that aggregates OpenStreetMap and other open geo sources. 2,500 free queries/day.
   * [graphhopper.com](https://www.graphhopper.com/) A free package for developers is offered for Routing, Route Optimization, Distance Matrix, Geocoding, Map Matching.
   * [datamaps.world](https://datamaps.world/) — The simple, yet powerful platform that gives you tools to visualize your geospatial data with a free tier.
   * [Foursquare](https://developer.foursquare.com/) - Location discovery, venue search, and context-aware content from Places API and Pilgrim SDK.
   * [geocod.io](https://www.geocod.io/) — Geocoding via API or CSV Upload. 2,500 free queries/day.
   * [gogeo.io](https://gogeo.io/) — Maps and geospatial services with an easy to use API and support for big data.
   * [carto.com](https://carto.com/) — Create maps and geospatial APIs from your data and public data.
   * [giscloud.com](https://www.giscloud.com/) — Visualize, analyze and share geo data online.
   * [mapbox.com](https://www.mapbox.com/) — Maps, geospatial services and SDKs for displaying map data.
   * [osmnames](https://osmnames.org/) — Geocoding, search results ranked by the popularity of related Wikipedia page.
   * [maptiler.com](https://www.maptiler.com/cloud/) — Vector maps, map services and SDKs for map visualisation. Free vector tiles with weekly update and four map styles.
   * [here](https://developer.here.com/) — APIs and SDKs for maps and location-aware apps. 250k transactions/month for free.
   * [stadiamaps.com](https://stadiamaps.com/) — Map tiles, routing, navigation, and other geospatial APIs. 2,500 free map views and API requests / day for non-commercial usage and testing.
   * [developers.arcgis.com](https://developers.arcgis.com) — APIs and SDKs for maps, geospatial data storage, analysis, geocoding, routing, and more across web, desktop, and mobile. 1,000,000 free basemap+geocode transactions, 40GB free tile+data storage per month.

## Package Build System

   * [build.opensuse.org](https://build.opensuse.org/) — Package build service for multiple distros (SUSE, EL, Fedora, Debian etc).
   * [copr.fedorainfracloud.org](https://copr.fedorainfracloud.org) — Mock-based RPM build service for Fedora and EL.
   * [help.launchpad.net](https://help.launchpad.net/Packaging) — Ubuntu and Debian build service.

## IDE and Code Editing

   * [Visual Studio Community](https://visualstudio.microsoft.com/vs/community/) — Fully-featured IDE with thousands of extensions, cross-platform app development (Microsoft extensions available for download for iOS and Android), desktop, web and cloud development, multi-language support (C#, C++, JavaScript, Python, PHP and more).
   * [ide.goorm.io](https://ide.goorm.io) goormIDE is full IDE on cloud. multi-language support, linux-based container via the fully-featured web-based terminal, port forwarding, custom url, real-time collaboration and chat, share link, Git/Subversion support. There are many more features (free tier includes 1GB RAM and 10GB Storage per container, 5 Container slot).
   * [cocalc.com](https://cocalc.com/) — (formerly SageMathCloud at cloud.sagemath.com) — Collaborative calculation in the cloud. Browser access to full Ubuntu with built-in collaboration and lots of free software for mathematics, science, data science, preinstalled: Python, LaTeX, Jupyter Notebooks, SageMath, scikitlearn, etc.
   * [wakatime.com](https://wakatime.com/) — Quantified self-metrics about your coding activity, using text editor plugins, limited plan for free.
   * [apiary.io](https://apiary.io/) — Collaborative design API with instant API mock and generated documentation (Free for unlimited API blueprints and unlimited user with one admin account and hosted documentation).
   * [mockable.io](https://www.mockable.io/) — Mockable is a simple configurable service to mock out RESTful API or SOAP web-services. This online service allows you to quickly define REST API or SOAP endpoints and have them return JSON or XML data.
   * [fakejson.com](https://fakejson.com/) — FakeJSON helps you quickly generate fake data using its API. Make an API request describing what you want and how you want it. The API returns it all in JSON. Speed up the go to market process for ideas and fake it till you make it.
   * [JSONPlaceholder](http://jsonplaceholder.typicode.com/) Some REST API endpoints that return some fake data in JSON format. The source code is also available if you would like to run the server locally.
   * [jetbrains.com](https://jetbrains.com/products.html) — Productivity tools, IDEs and deploy tools (aka PyCharm, Webstorm, etc). Free license for students, teachers, Open Source and user groups.
   * [codepen.io](https://codepen.io/) — CodePen is a playground for the front end side of the web.
   * [jsfiddle.net](https://jsfiddle.net/) — JS Fiddle is a playground and code sharing site of front end web, support collaboration as well.
   * [jsbin.com](https://jsbin.com) — JS Bin is another playground and code sharing site of front end web (HTML, CSS and JavaScript. Also supports Markdown, Jade and Sass).
   * [repl.it](https://repl.it/) — A cloud coding environment for various program languages.
   * [codesandbox.io](https://codesandbox.io/) — Online Playground for React, Vue, Angular, Preact and more.
   * [stackblitz.com](https://stackblitz.com/) — Online VS Code IDE for Angular & React.
   * [cacher.io](https://www.cacher.io) — Code snippet organizer with labels and support for 100+ programming languages.
   * [gitpod.io](https://www.gitpod.io) — Instant, ready-to-code dev environments for GitHub projects. Free for open source.
   * [Katacoda](https://katacoda.com) — Interactive learning and training platform for software engineers helping developers learn and companies increase adoption.
   * [JDoodle](https://www.jdoodle.com) — Online compiler and editor for more than 60 programming languages with a free plan for REST API code compiling up to 200 credits per day.
   * [Atom](https://atom.io/) - Atom is a hackable text editor built on Electron.
   * [Visual Studio Code](https://code.visualstudio.com/) - Code editor redefined and optimized for building and debugging modern web and cloud applications. Developed by Microsoft for Windows, macOS and Linux.
   * [VSCodium](https://vscodium.com/) - Community-driven, without telemetry/tracking, and freely-licensed binary distribution of Microsoft’s editor VSCode
   * [Eclipse Che](https://www.eclipse.org/che/) - Web based and Kubernetes-Native IDE for Developer Teams with multi-language support. Open Source and community driven. An hosted version is available at [che.openshift.io](https://che.openshift.io/)

## Analytics, Events and Statistics

   * [analytics.google.com](https://analytics.google.com/) — Google Analytics
   * [www.heatlyanalytics.com](https://www.heatlyanalytics.com) — Free Heatmap tool to understand UI/UX.
   * [heap.io](https://heap.io) — Automatically captures every user action in iOS or web apps. Free for up to 5,000 visits/month
   * [sematext.com](https://sematext.com/cloud/) — Free for up to 50 K actions/month, 1-day data retention, unlimited dashboards, users, etc.
   * [usabilityhub.com](https://usabilityhub.com/) — Test designs and mockups on real people, track visitors. Free for one user, unlimited tests
   * [mixpanel.com](https://mixpanel.com/) — Free 25,000 points or 200,000 with their badge on your site
   * [amplitude.com](https://amplitude.com/) — 1 million monthly events, up to 2 apps
   * [keen.io](https://keen.io/) — Custom Analytics for data collection, analysis and visualization. 50,000 events/month free
   * [metrica.yandex.com](https://metrica.yandex.com/) — Unlimited free analytics
   * [hotjar.com](https://www.hotjar.com/) — Per site: 2,000 pages views/day, 3 heatmaps, data stored for 3 months,...
   * [imprace.com](https://imprace.com/) — Landing page analysis with suggestions to improve bounce rates. Free 5 landing pages/domain
   * [optimizely.com](https://www.optimizely.com) — A/B Testing solution, free starter plan, 1 website, 1 iOS and 1 Android app
   * [expensify.com](https://www.expensify.com/) — Expense reporting, free personal reporting approval workflow
   * [Moesif](https://www.moesif.com) — API analytics for REST and GraphQL. (Free up to 500,000 API calls/mo)
   * [quantcast.com](https://www.quantcast.com/products/measure-audience-insights/) — Unlimited free analytics
   * [getinsights.io](https://getinsights.io) - Privacy-focused, cookie free analytics, free for up to 5k events/month.

## Visitor Session Recording
   * [FullStory.com](https://www.fullstory.com) — 1,000 sessions/month with 1 month data retention and 3 user seats. More information [here](https://help.fullstory.com/hc/en-us/articles/360020623354-FullStory-Free-Edition).
   * [inspectlet.com](https://www.inspectlet.com/) — 100 sessions/month free for 1 website
   * [mousestats.com](https://www.mousestats.com/) — 100 sessions/month free for 1 website
   * [hotjar.com](https://www.hotjar.com/) — Per site: 2,000 pages views/day, 3 heatmaps, data stored for 3 months,...
   * [usersurge.com](https://www.usersurge.com/) — 250K sessions per month for individuals.
   * [smartlook.com](https://www.smartlook.com/) — free packages for web and mobile apps (1500 sessions/month), 3 heatmaps, 1 funnel, 1-month data history
   * [mouseflow.com](https://mouseflow.com/) — 100 sessions/month free for 1 website

## International Mobile Number Verification API and SDK
  * [cognalys.com](https://cognalys.com/) — Freemium mobile number verification through an innovative and reliable method than using SMS gateway. Free 10 tries and 15 verifications/day
  * [numverify.com](https://numverify.com/) — Global phone number validation and lookup JSON API. 250 API requests/month
  * [veriphone.io](https://veriphone.io/) — Global phone number verification in a free, fast, reliable JSON API. 1000 requests/month

## Payment and Billing Integration

  * [currencylayer.com](https://currencylayer.com/) — Reliable Exchange Rates and Currency Conversion for your Business, 1,000 API requests/month free
  * [vatlayer.com](https://vatlayer.com/) — Instant VAT number validation and EU VAT rates API, free 100 API requests/month
  * [fraudlabspro.com](https://www.fraudlabspro.com) — Help merchants to prevent payment fraud and chargebacks. Free Micro Plan available with 500 queries/month.
  * [exchangerate-api.com](https://www.exchangerate-api.com) - An easy to use currency conversion JSON API. Free tier with no request limit.
  * [currencystack.io](https://currencystack.io/) — Production-ready real-time exchange rates for 154 currencies.
  * [mailpop.in](https://mailpop.in) - Get the most of your Stripe notifications with contextualized information.

## Docker Related

  * [Docker Hub](https://hub.docker.com) — One free private repository and unlimited public repositories to build and store Docker images
  * [quay.io](https://quay.io/) — Build and store container images with unlimited free public repositories
  * [canister.io](https://canister.io/) — 20 free private repositories for developers, 30 free private repositories for teams to build and store Docker images
  * [Whales](https://github.com/Gueils/whales) — A tool to automatically dockerize your applications for free.
  * [PWD](https://labs.play-with-docker.com/) — Play with Docker. A simple, interactive and fun playground to learn Docker
  * [Gitlab](https://gitlab.com) - Per-repo container registry.  10GB limit.

## Vagrant Related

  * [app.vagrantup.com](https://app.vagrantup.com) - HashiCorp Vagrant Cloud. Vagrant box hosting.
  * [vagrantbox.es](https://www.vagrantbox.es/) — An alternative public box index

## Dev Blogging Sites

  * [dev.to](https://dev.to/) - Where programmers share ideas and help each other grow.
  * [medium.com](https://medium.com/) — Get smarter about what matters to you.
  * [hashnode.com](https://hashnode.com/) — Hassle-free Blogging Software for Developers!.

## Miscellaneous
  * [docsapp.io](https://www.docsapp.io/) — Easiest way to publish documentation, free for Open Source
  * [fullcontact.com](https://www.fullcontact.com/developer/pricing/) — Help your users know more about their contacts by adding social profile into your app. 500 free Person API matches/month
  * [superfeedr.com](https://superfeedr.com/) — Real-time PubSubHubbub compliant feeds, export, analytics. Free with less customization
  * [screenshotlayer.com](https://screenshotlayer.com/) — Capture highly customizable snapshots of any website. Free 100 snapshots/month
  * [screenshotmachine.com](https://www.screenshotmachine.com/) — Capture 100 snapshots/month, png, gif and jpg, including full-length captures, not only home page
  * [readme.com](https://readme.com/) — Beautiful documentation made easy, free for Open Source: see [here](https://readme.readme.io/docs/open-source).
  * [http2.pro](https://http2.pro) — HTTP/2 protocol readiness test and client HTTP/2 support detection API.
  * [SurveyMonkey.com](https://www.surveymonkey.com) — Create online surveys. Analyze the results online.  Free plan allows only 10 questions and 100 responses per survey.
  * [Filly](https://fill.ly) — Boost your web development workflow by reusing manual actions done previously on your app. Form filler for improved team collaboration.
  * [ReqBin](https://www.reqbin.com/) — Post HTTP Requests Online. Popular Request Methods include GET, POST, PUT, DELETE, and HEAD. Supports Headers and Token Authentication. Includes a basic login system for saving your requests.
  * [PDFMonkey](https://www.pdfmonkey.io/) — Manage PDF templates in a dashboard, call the API with dynamic data, download your PDF. Offers 1000 free documents per month.
  * [FOSSA](https://fossa.com/) - Scalable, end-to-end management for third-party code, license compliance and vulnerabilities.
  * [ConfigCat](https://configcat.com) - Cross-platform feature flag service. SDKs for all major languages. Free plan up to 10 flags, 2 environments, 1 product and 5 Million requests per month. Unlimited user seats. Students get 100 flags and 100 Million requests per month for free.

## Other Free Resources
  * [github.com — FOSS for Dev](https://github.com/tvvocold/FOSS-for-Dev) — A hub of free and Open Source software for developers
  * [getawesomeness](https://getawesomeness.herokuapp.com) — Retrieve all amazing awesomeness from GitHub... a must see
  * [education.github.com](https://education.github.com/pack) — Collection of free services for students. Registration required
  * [Framacloud](https://degooglisons-internet.org/en/list/) — A list of Free/Libre Open Source Software and SaaS by the French non-profit [Framasoft](https://framasoft.org/en/).
