using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Web;

namespace Atomus.Net
{
    public class Mail : IMail
    {
        public Mail()
        {
            ServicePointManager.ServerCertificateValidationCallback += ServerCertificateValidationCallback;
        }

        MailMessage IMail.CreateMailMessage(string from, string to, string subject, string body, Encoding encoding, bool isBodyHtml, IAttachmentBytes attachmentBytes, MailPriority priority, DeliveryNotificationOptions deliveryNotificationOptions)
        {
            return ((IMail)this).CreateMailMessage(from, to, "", "", "", subject, body, encoding, isBodyHtml, attachmentBytes, priority, deliveryNotificationOptions);
        }
        MailMessage IMail.CreateMailMessage(string from, string to, string subject, string body, Encoding encoding, bool isBodyHtml, List<IAttachmentBytes> attachmentBytes, MailPriority priority, DeliveryNotificationOptions deliveryNotificationOptions)
        {
            return ((IMail)this).CreateMailMessage(from, to, "", "", "", subject, body, encoding, isBodyHtml, attachmentBytes, priority, deliveryNotificationOptions);
        }
        MailMessage IMail.CreateMailMessage(string from, string to, string subject, string body, Encoding encoding, bool isBodyHtml, MailPriority priority, DeliveryNotificationOptions deliveryNotificationOptions)
        {
            return ((IMail)this).CreateMailMessage(from, to, "", "", "", subject, body, encoding, isBodyHtml, default(FileInfo[]), priority, deliveryNotificationOptions);
        }
        MailMessage IMail.CreateMailMessage(string from, string to, string subject, string body, Encoding encoding, bool isBodyHtml, string filePath, MailPriority priority, DeliveryNotificationOptions deliveryNotificationOptions)
        {
            return ((IMail)this).CreateMailMessage(from, to, "", "", "", subject, body, encoding, isBodyHtml, filePath, priority, deliveryNotificationOptions);
        }
        MailMessage IMail.CreateMailMessage(string from, string to, string subject, string body, Encoding encoding, bool isBodyHtml, string[] filePaths, MailPriority priority, DeliveryNotificationOptions deliveryNotificationOptions)
        {
            return ((IMail)this).CreateMailMessage(from, to, "", "", "", subject, body, encoding, isBodyHtml, filePaths, priority, deliveryNotificationOptions);
        }
        MailMessage IMail.CreateMailMessage(string from, string to, string subject, string body, Encoding encoding, bool isBodyHtml, FileInfo fileInfo, MailPriority priority, DeliveryNotificationOptions deliveryNotificationOptions)
        {
            return ((IMail)this).CreateMailMessage(from, to, "", "", "", subject, body, encoding, isBodyHtml, fileInfo, priority, deliveryNotificationOptions);
        }
        MailMessage IMail.CreateMailMessage(string from, string to, string subject, string body, Encoding encoding, bool isBodyHtml, FileInfo[] fileInfos, MailPriority priority, DeliveryNotificationOptions deliveryNotificationOptions)
        {
            return ((IMail)this).CreateMailMessage(from, to, "", "", "", subject, body, encoding, isBodyHtml, fileInfos, priority, deliveryNotificationOptions);
        }
        MailMessage IMail.CreateMailMessage(string from, string to, string subject, string body, Encoding encoding, bool isBodyHtml, Attachment attachment, MailPriority priority, DeliveryNotificationOptions deliveryNotificationOptions)
        {
            return ((IMail)this).CreateMailMessage(from, to, "", "", "", subject, body, encoding, isBodyHtml, attachment, priority, deliveryNotificationOptions);
        }
        MailMessage IMail.CreateMailMessage(string from, string to, string subject, string body, Encoding encoding, bool isBodyHtml, List<Attachment> attachments, MailPriority priority, DeliveryNotificationOptions deliveryNotificationOptions)
        {
            return ((IMail)this).CreateMailMessage(from, to, "", "", "", subject, body, encoding, isBodyHtml, attachments, priority, deliveryNotificationOptions);
        }

        MailMessage IMail.CreateMailMessage(string from, string to, string cc, string bcc, string replyTo, string subject, string body, Encoding encoding, bool isBodyHtml, MailPriority priority, DeliveryNotificationOptions deliveryNotificationOptions)
        {
            return ((IMail)this).CreateMailMessage(from, to, "", "", "", subject, body, encoding, isBodyHtml, default(FileInfo[]), priority, deliveryNotificationOptions);
        }
        MailMessage IMail.CreateMailMessage(string from, string to, string cc, string bcc, string replyTo, string subject, string body, Encoding encoding, bool isBodyHtml, IAttachmentBytes attachmentBytes, MailPriority priority, DeliveryNotificationOptions deliveryNotificationOptions)
        {
            return ((IMail)this).CreateMailMessage(from, to, cc, bcc, replyTo, subject, body, encoding, isBodyHtml
                , new Attachment(new MemoryStream(attachmentBytes.Bytes), attachmentBytes.FileName, attachmentBytes.MediaType), priority, deliveryNotificationOptions);
        }
        MailMessage IMail.CreateMailMessage(string from, string to, string cc, string bcc, string replyTo, string subject, string body, Encoding encoding, bool isBodyHtml, List<IAttachmentBytes> attachmentBytes, MailPriority priority, DeliveryNotificationOptions deliveryNotificationOptions)
        {
            List<Attachment> attachments;

            attachments = null;

            if (attachmentBytes != null && attachmentBytes.Count > 0)
            {
                attachments = new List<Attachment>();

                foreach (IAttachmentBytes attachment in attachmentBytes)
                    attachments.Add(new Attachment(new MemoryStream(attachment.Bytes), attachment.FileName, attachment.MediaType));
            }

            return ((IMail)this).CreateMailMessage(from, to, cc, bcc, replyTo, subject, body, encoding, isBodyHtml, attachments, priority, deliveryNotificationOptions);
        }
        MailMessage IMail.CreateMailMessage(string from, string to, string cc, string bcc, string replyTo, string subject, string body, Encoding encoding, bool isBodyHtml, string filePath, MailPriority priority, DeliveryNotificationOptions deliveryNotificationOptions)
        {
            if (filePath != null)
                return ((IMail)this).CreateMailMessage(from, to, cc, bcc, replyTo, subject, body, encoding, isBodyHtml, new FileInfo[] { new FileInfo(filePath) }, priority, deliveryNotificationOptions);
            else
                return ((IMail)this).CreateMailMessage(from, to, cc, bcc, replyTo, subject, body, encoding, isBodyHtml, default(FileInfo[]), priority, deliveryNotificationOptions);
        }
        MailMessage IMail.CreateMailMessage(string from, string to, string cc, string bcc, string replyTo, string subject, string body, Encoding encoding, bool isBodyHtml, string[] filePaths, MailPriority priority, DeliveryNotificationOptions deliveryNotificationOptions)
        {
            List<FileInfo> fileInfos;

            if (filePaths != null)
            {
                fileInfos = new List<FileInfo>();

                foreach (string tmp in filePaths)
                    if (tmp != null && tmp != null)
                        fileInfos.Add(new FileInfo(tmp));

                return ((IMail)this).CreateMailMessage(from, to, cc, bcc, replyTo, subject, body, encoding, isBodyHtml, fileInfos.ToArray(), priority, deliveryNotificationOptions);
            }
            else
                return ((IMail)this).CreateMailMessage(from, to, cc, bcc, replyTo, subject, body, encoding, isBodyHtml, default(FileInfo[]), priority, deliveryNotificationOptions);
        }
        MailMessage IMail.CreateMailMessage(string from, string to, string cc, string bcc, string replyTo, string subject, string body, Encoding encoding, bool isBodyHtml, FileInfo fileInfo, MailPriority priority, DeliveryNotificationOptions deliveryNotificationOptions)
        {
            if (fileInfo != null)
                return ((IMail)this).CreateMailMessage(from, to, cc, bcc, replyTo, subject, body, encoding, isBodyHtml, new FileInfo[] { fileInfo }, priority, deliveryNotificationOptions);
            else
                return ((IMail)this).CreateMailMessage(from, to, cc, bcc, replyTo, subject, body, encoding, isBodyHtml, default(FileInfo[]), priority, deliveryNotificationOptions);
        }
        MailMessage IMail.CreateMailMessage(string from, string to, string cc, string bcc, string replyTo, string subject, string body, Encoding encoding, bool isBodyHtml, FileInfo[] fileInfos, MailPriority priority, DeliveryNotificationOptions deliveryNotificationOptions)
        {
            List<Attachment> attachments;

            attachments = null;

            if (fileInfos != null && fileInfos.Length > 0)
            {
                attachments = new List<Attachment>();

                foreach (FileInfo fileInfo in fileInfos)
                    if (fileInfo != null)
                        attachments.Add(new Attachment(new StreamReader(fileInfo.FullName).BaseStream, fileInfo.Name, MimeMapping.GetMimeMapping(fileInfo.FullName)));
            }

            return ((IMail)this).CreateMailMessage(from, to, cc, bcc, replyTo, subject, body, encoding, isBodyHtml, attachments, priority, deliveryNotificationOptions);
        }
        MailMessage IMail.CreateMailMessage(string from, string to, string cc, string bcc, string replyTo, string subject, string body, Encoding encoding, bool isBodyHtml, Attachment attachment, MailPriority priority, DeliveryNotificationOptions deliveryNotificationOptions)
        {
            if (attachment != null)
                return ((IMail)this).CreateMailMessage(from, to, cc, bcc, replyTo, subject, body, encoding, isBodyHtml, new List<Attachment> { attachment }, priority, deliveryNotificationOptions);
            else
                return ((IMail)this).CreateMailMessage(from, to, cc, bcc, replyTo, subject, body, encoding, isBodyHtml, default(List<Attachment>), priority, deliveryNotificationOptions);
        }
        MailMessage IMail.CreateMailMessage(string from, string to, string cc, string bcc, string replyTo, string subject, string body, Encoding encoding, bool isBodyHtml, List<Attachment> attachments, MailPriority priority, DeliveryNotificationOptions deliveryNotificationOptions)
        {
            MailMessage message = new MailMessage
            {
                From = new MailAddress(from, null, encoding)
            };
            this.AddMailAddressCollection(message.To, to, encoding);
            this.AddMailAddressCollection(message.CC, cc, encoding);
            this.AddMailAddressCollection(message.Bcc, bcc, encoding);
            this.AddMailAddressCollection(message.ReplyToList, replyTo, encoding);

            message.IsBodyHtml = isBodyHtml;

            message.SubjectEncoding = encoding;
            message.BodyEncoding = encoding;

            message.Subject = subject;
            message.Body = body;

            message.Priority = priority;
            message.DeliveryNotificationOptions = deliveryNotificationOptions;

            if (attachments != null && attachments.Count > 0)
                foreach (Attachment attachment in attachments)
                    message.Attachments.Add(attachment);

            message.Headers.Add("Atomus", "Atomus Framework");

            return message;
        }

        void IMail.Send(string profileName, MailMessage mailMessage)
        {
            try
            {
                this.CreateSmtpClient(profileName).Send(mailMessage);// 동기로 메일을 보낸다.
            }
            catch (Exception ex)
            {
                throw ex;
            }
            finally
            {
            }
        }
        async void IMail.SendAsync(string profileName, MailMessage mailMessage)
        {
            try
            {
                await this.CreateSmtpClient(profileName).SendMailAsync(mailMessage);// 동기로 메일을 보낸다.
            }
            catch (Exception ex)
            {
                throw ex;
            }
            finally
            {
            }
        }

        void IMail.Send(string host, int port, bool UseDefaultCredentials, bool EnableSsl, SmtpDeliveryMethod network, NetworkCredential networkCredential, MailMessage mailMessage)
        {
            try
            {
                this.CreateSmtpClient(host, port, UseDefaultCredentials, EnableSsl, network, networkCredential).Send(mailMessage);// 동기로 메일을 보낸다.
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
        async void IMail.SendAsync(string host, int port, bool UseDefaultCredentials, bool EnableSsl, SmtpDeliveryMethod network, NetworkCredential networkCredential, MailMessage mailMessage)
        {
            try
            {
                await this.CreateSmtpClient(host, port, UseDefaultCredentials, EnableSsl, network, networkCredential).SendMailAsync(mailMessage);// 동기로 메일을 보낸다.
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        private SmtpClient CreateSmtpClient(string profileName)
        {
            string profile;
            string host = "";
            int port = 587;
            bool useDefaultCredentials = false;
            bool enableSsl = false;
            SmtpDeliveryMethod smtpDeliveryMethod = SmtpDeliveryMethod.Network;
            string userName = "";
            string password = "";

            profile = ConfigurationManager.AppSettings[string.Format("EmailProfile.{0}", profileName)];

            var cs = (from a in profile.Split(';')
                      where a.Contains("Host")
                      select a);

            if (cs != null && cs.Count() == 1)
            {
                var ic = cs.ToList()[0].Split('=');
                if (ic != null && ic.Length == 2) host = ic[1].Trim();
            }

            cs = (from a in profile.Split(';')
                  where a.Contains("Port")
                  select a);

            if (cs != null && cs.Count() == 1)
            {
                var ic = cs.ToList()[0].Split('=');
                if (ic != null && ic.Length == 2) port = ic[1].Trim().ToInt();
            }

            cs = (from a in profile.Split(';')
                  where a.Contains("UseDefaultCredentials")
                  select a);

            if (cs != null && cs.Count() == 1)
            {
                var ic = cs.ToList()[0].Split('=');
                if (ic != null && ic.Length == 2) useDefaultCredentials = ic[1].Trim().ToBool();
            }

            cs = (from a in profile.Split(';')
                  where a.Contains("EnableSsl")
                  select a);

            if (cs != null && cs.Count() == 1)
            {
                var ic = cs.ToList()[0].Split('=');
                if (ic != null && ic.Length == 2) enableSsl = ic[1].Trim().ToBool();
            }

            cs = (from a in profile.Split(';')
                  where a.Contains("SmtpDeliveryMethod")
                  select a);

            if (cs != null && cs.Count() == 1)
            {
                var ic = cs.ToList()[0].Split('=');
                if (ic != null && ic.Length == 2) smtpDeliveryMethod = (SmtpDeliveryMethod)Enum.Parse(typeof(SmtpDeliveryMethod), ic[1].Trim());
            }

            cs = (from a in profile.Split(';')
                  where a.Contains("UserName")
                  select a);

            if (cs != null && cs.Count() == 1)
            {
                var ic = cs.ToList()[0].Split('=');
                if (ic != null && ic.Length == 2) userName = ic[1].Trim();
            }

            cs = (from a in profile.Split(';')
                  where a.Contains("Password")
                  select a);

            if (cs != null && cs.Count() == 1)
            {
                var ic = cs.ToList()[0].Split('=');
                if (ic != null && ic.Length == 2) password = ic[1].Trim();
            }

            return this.CreateSmtpClient(host, port, useDefaultCredentials, enableSsl, smtpDeliveryMethod, new NetworkCredential(userName, password));
        }
        private SmtpClient CreateSmtpClient(string host, int port, bool UseDefaultCredentials, bool EnableSsl, SmtpDeliveryMethod network, NetworkCredential networkCredential)
        {
            SmtpClient client =  new SmtpClient(host, port)
            {
                UseDefaultCredentials = UseDefaultCredentials, // 시스템에 설정된 인증 정보를 사용하지 않는다.
                EnableSsl = EnableSsl,  // SSL을 사용한다.
                DeliveryMethod = network, // 이걸 하지 않으면 Gmail에 인증을 받지 못한다.
                Credentials = networkCredential
            };

            client.SendCompleted += Client_SendCompleted;

            return client;
        }

        private void AddMailAddressCollection(MailAddressCollection mailAddresses, string mailAddress, string displayName, Encoding encoding)
        {
            this.AddMailAddressCollection(mailAddresses, string.Format("{0} <{1}>", displayName, mailAddress), encoding);
        }
        private void AddMailAddressCollection(MailAddressCollection mailAddresses, string mailmailAddressList, Encoding encoding)
        {
            string[] tmps;

            if (mailmailAddressList == null || mailmailAddressList == "")
                return;

            //mailAddresses = new System.Net.Mail.MailAddressCollection();

            if (mailmailAddressList.Contains(";"))
            {
                tmps = mailmailAddressList.Split(';');

                foreach (string tmp in tmps)
                    if (tmp != null && tmp.Trim() != "")
                        mailAddresses.Add(new System.Net.Mail.MailAddress(tmp, null, encoding));
            }
            else
                mailAddresses.Add(new System.Net.Mail.MailAddress(mailmailAddressList, null, encoding));
        }

        private void Client_SendCompleted(object sender, System.ComponentModel.AsyncCompletedEventArgs e)
        {
            ((SmtpClient)sender)?.Dispose();
            //MessageBox.Show(e.ToString());
        }
        private static bool ServerCertificateValidationCallback(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            // If the certificate is a valid, signed certificate, return true.
            if (sslPolicyErrors == SslPolicyErrors.None)
            {
                return true;
            }

            // If there are errors in the certificate chain, look at each error to determine the cause.
            if ((sslPolicyErrors & SslPolicyErrors.RemoteCertificateChainErrors) != 0)
            {
                if (chain != null && chain.ChainStatus != null)
                {
                    foreach (X509ChainStatus status in chain.ChainStatus)
                    {
                        if ((certificate.Subject == certificate.Issuer) &&
                           (status.Status == X509ChainStatusFlags.UntrustedRoot))
                        {
                            // Self-signed certificates with an untrusted root are valid. 
                            continue;
                        }
                        else
                        {
                            if (status.Status != X509ChainStatusFlags.NoError)
                            {
                                // If there are any other errors in the certificate chain, the certificate is invalid,
                                // so the method returns false.
                                return false;
                            }
                        }
                    }
                }

                // When processing reaches this line, the only errors in the certificate chain are 
                // untrusted root errors for self-signed certificates. These certificates are valid
                // for default Exchange server installations, so return true.
                return true;
            }
            else
            {
                // In all other cases, return false.
                return false;
            }
        }
    }
}
