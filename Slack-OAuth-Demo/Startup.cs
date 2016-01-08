using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(Slack_OAuth_Demo.Startup))]
namespace Slack_OAuth_Demo
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
