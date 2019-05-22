using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Certes;
using Certes.Acme;
using Certes.Acme.Resource;
using Certes.Pkcs;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace encrypt_all_the_time
{
    public class Startup
    {
        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.Map("/.well-known/acme-challenge", sub =>
     {
         sub.Run(async context =>
         {
             var path = context.Request.Path.ToUriComponent();
             if (path?.Length > 1 && path.StartsWith("/"))
             {
                 context.Response.ContentType = "plain/text";
                 await context.Response.WriteAsync(File.ReadAllText($"{path.Substring(1)}"));

             }
         });
     });
            app.Run(async (context) =>
            {
                try
                {
                    const string ngrokUrl = "fc404848.ngrok.io";
                    const string userEmailAddress = "asdasd@adsdasd.com";
                    var acme = new AcmeContext(WellKnownServers.LetsEncryptStagingV2);
                    var account = await acme.NewAccount(userEmailAddress, true);

                    var order = await acme.NewOrder(new[] { ngrokUrl });

                    var authz = (await order.Authorizations()).First();
                    var httpChallenge = await authz.Http();
                    var keyAuthz = httpChallenge.KeyAuthz;

                    File.WriteAllText("./" + httpChallenge.Token, keyAuthz);

                    var validaion = await httpChallenge.Validate();
                    while (validaion.Status.Value == ChallengeStatus.Pending)
                    {
                        await Task.Delay(10000);
                        validaion = await httpChallenge.Validate();
                        Console.WriteLine(validaion.Status.Value);
                    }

                    if (validaion.Status == ChallengeStatus.Valid)
                    {
                        var privateKey = KeyFactory.NewKey(KeyAlgorithm.ES256);
                        var cert = await order.Generate(new CsrInfo
                        {
                            CountryName = "US",
                            State = "New York",
                            Locality = "New York",
                            Organization = "Anaru",
                            OrganizationUnit = "Dev",
                            CommonName = ngrokUrl,
                        }, privateKey);


                        var certPem = cert.ToPem();
                        var pfxBuilder = cert.ToPfx(privateKey);
                        var pfx = pfxBuilder.Build("my-cert", "abcd1234");

                        File.WriteAllBytes("./my-free-cert.pfx", pfx);
                        await acme.RevokeCertificate(cert.Certificate.ToDer(), RevocationReason.AffiliationChanged, privateKey);

                        await context.Response.WriteAsync("Woo!");


                    }

                    File.Delete("./" + httpChallenge.Token);
                }
                catch (Exception exception)
                {
                    Console.WriteLine("shit fucked up", exception);
                    throw;
                }

            });


        }
    }
}
