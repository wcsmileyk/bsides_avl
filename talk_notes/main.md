## Background

Procurement cycle takes a lot of time. It's really hard to find numbers on how long it takes, and even harder to find numbers on how long it takes from gap identification to deployment. But according Capterra published a 2013 report (https://www.capterra.com/software-buying-trends-2013) indicated that on average if over 6 people are involved the procurement (not deployment) process will take over 6 months. And the Harvar Business Review (https://hbr.org/2017/03/the-new-sales-imperative) / CEB research have found that on average 6.8 people are involved in procurement right now. In the research the discuss, it appears that even short procurement is about 2 months. So, since we're security people and not procurement people and our brains are already full of research and data constantly, I'm going to feel comfortable saying purchasing software takes months, not days. Deployment is another factor. I don't have research that isn't my personal experience. But I have a _lot_ of personal experience. I've been deploying security solutions for a long time, and feel comfortable saying that those deployments are also on average measured in months (once purchase is complete) not necessarily days. Though this can vary significantly. 

### Why is that important?

Because these tools aren't being purchased for fun. Defensive teams have identified gaps they have in being able to protect their network and respond to incidents, and these tools need to fill them. So in a good case scenario it's going to take you multiple months from identifying that gap to having a tool that can fill it. You're already getting behind right there. But even after you get the tool, get that gap filled, the environment and threats are adapting and changing. Vendors are starting to acknowledge that and are making their tools more extensible and customizable to try and keep of with these threats. It's still not perfect yet, though. 

### Engineering Capability

Now we're starting to touch on my point. In the last 5 years I've spent all my time working with defensive security teams. This means Incident Response/SOC teams, Security Operations, Threat/Vulnerabiliyt management, Security Monitoring, etc. I can think of only a tiny fraction of those customers that have invested any even moderate amount into an internal engineering resource of any kind. They will ocassionally pay consultants, but normally they are looking for vendors to deploy and customize their tools for them. Generally, this isn't a terrible idea. The vendor knows their tool and they have the resources for it. But these teams could easily solve a lot of their own problems. Adapt their current tools faster, fill gaps quicker (even if only with a temporary solution), adjust to the threat landscape as it evolves. 

### Offensive/Red Team and Threat Research are investing

Those types of teams have long been investing in engineering ability, almost every red teamer could pretty easily write a fairly complex script to automate part of their workflow. Malware researchers, for obvious reasons, need to be very familiar with code and computer science. But defensive security teams seem to believe they just need to use vendor tools built for the masses to secure their enterprises. 

### I'm speaking from my own experiences as much as the customers I have seen

I started off in the Marine Corps at a time when they were not investing or tolerant of building our own tools, even simple ones. The idea of learning python wasn't even a question, and if you knew it already good luck getting a system that has it on there and being allowed to write anything. We were at the whim of our tools, and we weren't innovative enough to keep up. Luckily we had a very very locked down network to start, and the attack surface was small. These days they've learned and really adjusted, as I understand it.

After I left the Marine Corps everything chagned. My first job had a very small budget, so we built everything. That's when I started learning to script and write simple apps to help us secure our very large enterprise. As I've worked my way through the vendor space and worked with a lot of customers I've found that's pretty unusual. But I've also found that even the tools I deploy with customers would benefit from the customer being able to build some basic tools of their own. 

### Other advantages

- Understand the tools you're buying/need to buy better. Be able to define requirements and understand complexity of those requirements a bit better
- Foster innovation and creativity in solving problems on your team. You won't be limited to thinking through a set of solutions that already exist
- Save money. I'm going to generally advise that any solution intended to become production/permanent solution be developed by professional software engineers. Either interanally or externally, and most importantly be fully supported by the vendor/maintainer. That may mean hiring a dedicated tool builder to productionize your prototypes, or more likely will me transitioning to a commercial solution when you're ready for that. Supporting it will generally be the biggest reason for this. If you invest in the engineering capability your team will likely be able to build a solution for most all your needs. But in the end your team is there to provide security to your organization, not support software. Presumably, at least.

# So let's build some stuff

Not really, live coding isn't in my skillset. Because I'm _*not*_ a developer. I've learned python, some JS and bit of C++ just to make my life and my customers' lives easier. But no one would consider me a true developer. But that's what we're talking about. I invested some extra time, often with very supportive employers, into adding tool building to my skillset. And to prep for this talk, I built some code and timed myself to show you how fast you can get a good enough solution online until you find or purchase a commercial or more professionalized solution. Or maybe it'll be good enough.

# The tools

The code examples I'm going to show are python. You don't need to know python, this isn't about that. I'll break the logic of each script down and talk about how I decided to do what I did and the time it took me to research/figure it out. 

## Ingesting Data

So we don't have a SIEM. No log analysis tool of any kind. We've requested one, but don't have it yet. Until we get one, we're going to be manually grepping/reviewing logs for problems, and taking forever to dig into incidents and possible security events. If your team has invested time and resources into developing an engineering/tool building capability it doesn't need to be too bad, though. It's unlikely your team will be able to build something as comprehensive as commercial SIEM, even less likely it'll be as fast as a commercial SIEM. But it's likely you can work with your full volume of logs, and relatively quickly identify security incidents of note without one. It'll just take a bit of up front time, but it will be less time than the multiple months it will take. 

So. Let's build something that will cover the ingestion, primary parsing of the tool. This area will be one of the few I'm going to use an already built tool for (minus the coding languages and libraries). Syslogng, rsyslog are open source and one of the two is already installed on essentially every *nix based distro that exists. And they're so good at their job, that a lot of SIEMs use them as their base syslog ingestion mechanism. It'd be silly to build your own solution (though you easily could) to do that piece. 


#### Architecture:

I've used the following architecture several times to mac an ad-hoc SIEM-like tool. It's very straight forward and easy to build, and also easy to extend:

	- rsyslog to receive syslog data
	- python log parsing engine
	- json files as a makeshift DB. (Adding a real DB is pretty simple in python with libraries like PeeWee and SQLAlchemy. And would make working with larger volumes a bit easier)
	- python built rule sets

#### Tips

	- Don't worry about it being perfect. If it's better than what you already have in place (nothing) it's at least close to succesful. If it increases your security posture it's definitely succesful. 
	- Don't reinvent the wheel (unless you want to and have time)
	- Don't prematurely optimize. Similar to not being perfect, but it's very easy with parsers/ingestors to think about all the possible fringe cases that you'll want to use it for later. Just write it for what you're using it for today and adjust later.
	- Consider logical ways to group data that works for what you'll be doing. In our case we only have a few log sources, so grouping by them will work at first.

	- Note on Windows. There is an entire discussion that can be had around Windows logging and automation for that. Having worked for a SIEM vendor and with several SIEM vendors, even most vendors really struggle with it for a variety of reasons. When working with python and the pywin library (unless you want to write a ton of byte code, one of the only ways to work with WinEvents in Python), encoding is going to be a big struggle, so will the pywin library itself (not incredibly well documented, for all it does). But it's definitely possible. It's just more time consuming, so put that in the con bucket when considering whether or not to build tools around it. I opted to stix to standard syslog for this to not eat up all my prep time on Windows parsing. 
