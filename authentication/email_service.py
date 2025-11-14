# authentication/email_service.py

from django.core.mail import send_mail
from django.conf import settings

# Note: The render_to_string and strip_tags imports are no longer needed
# as we are building the HTML directly in this file for clarity.
# In a larger project, you would move the HTML into .html template files.


class SVAEmailTemplate:
    """
    Unified email template system for SVA, rebuilt with email-safe best practices.
    - All critical styles are inlined for maximum compatibility (Gmail, Outlook).
    - Layout is built with <table> elements, not divs.
    - Modern CSS (animations, shadows) is replaced with compatible alternatives.
    - A minimal <style> block is retained for progressive enhancement (dark mode, responsiveness).
    """

    @staticmethod
    def get_head_styles():
        """
        Get the CSS for the <head>. This is for progressive enhancement.
        Email clients that support it will use it; others will ignore it.
        The core email design DOES NOT depend on this CSS.
        """
        return """
        /* --- Dark Mode Support --- */
        :root {
            color-scheme: light dark;
            supported-color-schemes: light dark;
        }
        @media (prefers-color-scheme: dark) {
            body { background-color: #1a1d1f !important; }
            .email-container { background-color: #1a1d1f !important; border-color: #2d3436 !important; }
            .content-bg { background-color: #1a1d1f !important; }
            .content-text, .content-text p { color: #adb5bd !important; }
            .greeting, .header-title { color: #f8f9fa !important; }
            .security-note-dark { background-color: #0d3330 !important; border-left-color: #20c997 !important; }
            .security-text-dark { color: #e9ecef !important; }
            .footer-bg { background-color: #0f1215 !important; }
            .footer-text { color: #6c757d !important; }
            .link-fallback a { color: #51cf66 !important; }
        }

        /* --- Responsive Design --- */
        @media only screen and (max-width: 600px) {
            body { font-size: 8px !important; }
            .email-wrapper { padding: 0px !important; font-size:1rem !important; }
            .content-cell { padding: 40px 24px !important; font-size:1rem !important; }
            .header-cell { padding: 40px 24px !important; font-size:1rem !important; }
            .button-cell { padding: 18px 36px !important; font-size:1rem !important; }
            .feature-stack { display: block !important; width: 100% !important; padding: 16px 0 !important; font-size: 8px !important; }
        }
        """

    @staticmethod
    def get_base_html_template():
        """Get the base HTML structure for all SVA emails, built with tables."""
        return """
        <!DOCTYPE html>
        <html lang="en" xmlns="http://www.w3.org/1999/xhtml" xmlns:o="urn:schemas-microsoft-com:office:office">
        <head>
            <meta charset="utf-8" />
            <meta name="viewport" content="width=device-width, initial-scale=1.0" />
            <meta name="x-apple-disable-message-reformatting" />
            <meta http-equiv="X-UA-Compatible" content="IE=edge" />
            <meta name="color-scheme" content="light dark" />
            <meta name="supported-color-schemes" content="light dark" />
            <title>{title}</title>
            <!--[if mso]>
            <noscript>
            <xml>
                <o:OfficeDocumentSettings>
                <o:PixelsPerInch>96</o:PixelsPerInch>
                </o:OfficeDocumentSettings>
            </xml>
            </noscript>
            <![endif]-->
            <style type="text/css">
                {styles}
            </style>
        </head>
        <body style="margin: 0; padding: 0; width: 100%; -webkit-text-size-adjust: 100%; background-color: #f8f9fa;">
            <table class="email-wrapper" role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="background-color: #f8f9fa;">
                <tr>
                    <td align="center" style="padding: 0px;">
                        <!--[if (gte mso 9)|(IE)]>
                        <table align="center" border="0" cellspacing="0" cellpadding="0">
                        <tr>
                        <td align="center" valign="top">
                        <![endif]-->
                        <table class="email-container" role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="margin: 0 auto; background-color: #ffffff; border-radius: 20px; overflow: hidden; border: 1px solid #dee2e6;">
                            
                            <!-- Shimmer Bar -->
                            <tr>
                                <td style="height: 4px; background-color: #20c997; background: linear-gradient(90deg, #20c997, #008080, #0ca678, #20c997);"></td>
                            </tr>
                            
                            <!-- Header Section -->
                            <tr>
                                <td class="header-cell" align="center" style="padding: 50px 40px; color: #ffffff; background-color: #008080; background: linear-gradient(135deg, #20c997 0%, #17a589 50%, #008080 100%);">
                                    <img src="https://getsva.com/assets/logo_light-CdL5_O1L.png" alt="SVA Logo" width="120" style="display: block; margin: 0 auto 24px auto; border-radius: 20px;">
                                    <h1 class="header-title" style="font-family: 'Inter', Arial, sans-serif; font-size: 32px; font-weight: 800; margin: 0 0 12px; color: #ffffff;">{header_title}</h1>
                                    <p style="font-family: 'Inter', Arial, sans-serif; font-size: 8px; font-weight: 500; margin: 0; color: #ffffff; opacity: 0.95;">{header_subtitle}</p>
                                </td>
                            </tr>

                            <!-- Main Content -->
                            <tr>
                                <td class="content-cell content-bg" align="left" style="padding: 56px 48px; background-color: #ffffff;">
                                    {content_body}
                                </td>
                            </tr>

                            <!-- Footer -->
                            <tr>
                                <td class="footer-bg" align="center" style="padding: 40px 30px; background-color: #f8f9fa; border-top: 1px solid #dee2e6;">
                                    <p class="footer-text" style="font-family: 'Inter', Arial, sans-serif; color: #6c757d; font-size: 14px; margin: 0 0 12px; line-height: 1.6;">
                                        This is an automated message. Please do not reply to this email.<br />
                                        © 2025 SVA Security Systems. All Rights Reserved.<br />
                                        <a href="#" style="color: #adb5bd; text-decoration: none;">Privacy Policy</a> &bull;
                                        <a href="#" style="color: #adb5bd; text-decoration: none;">Terms of Service</a> &bull;
                                        <a href="#" style="color: #adb5bd; text-decoration: none;">Unsubscribe</a>
                                    </p>
                                </td>
                            </tr>
                        </table>
                        <!--[if (gte mso 9)|(IE)]>
                        </td>
                        </tr>
                        </table>
                        <![endif]-->
                    </td>
                </tr>
            </table>
        </body>
        </html>
        """

    @staticmethod
    def create_email_html(title, header_title, header_subtitle, content_body):
        """Create a complete email HTML with consistent styling"""
        styles = SVAEmailTemplate.get_head_styles()
        template = SVAEmailTemplate.get_base_html_template()
        
        return template.format(
            title=title,
            styles=styles,
            header_title=header_title,
            header_subtitle=header_subtitle,
            content_body=content_body
        )


def send_verification_email(email, token, frontend_url=None):
    if not frontend_url:
        frontend_url = "http://localhost:8080"
    
    verification_url = f"{frontend_url}/verify-email?token={token}"
    subject = "Verify Your Email - SVA Zero-Knowledge Authentication"
    
    content_body = f"""
        <h2 class="greeting" style="font-family: 'Inter', Arial, sans-serif; font-size: 34px; font-weight: 800; margin: 0 0 24px; color: #008080; line-height: 1.2;">Welcome to SVA!</h2>
        <p class="content-text" style="font-family: 'Inter', Arial, sans-serif; font-size: 17px; color: #495057; margin: 0 0 24px; line-height: 1.8;">
            Thank you for choosing SVA. To complete your account setup and activate your Universal Profile, please verify your email address.
        </p>

        <!-- Bulletproof Button -->
        <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="margin: 48px 0;">
            <tr>
                <td align="center">
                    <table role="presentation" border="0" cellpadding="0" cellspacing="0">
                        <tr>
                            <td class="button-cell" align="center" bgcolor="#20c997" style="border-radius: 10px; background: linear-gradient(135deg, #20c997 0%, #008080 100%);">
                                <a href="{verification_url}" target="_blank" style="font-family: 'Inter', Arial, sans-serif; font-size: 17px; font-weight: 700; color: #ffffff; text-decoration: none; display: inline-block; padding: 20px 48px; border-radius: 10px; border: 1px solid #20c997;">
                                    Verify Email Address &rarr;
                                </a>
                            </td>
                        </tr>
                    </table>
                </td>
            </tr>
        </table>
        
        <!-- Security Note -->
        <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="margin: 48px 0;">
            <tr>
                <td class="security-note-dark" style="background-color: #e6fcf5; border-left: 5px solid #20c997; padding: 24px 28px; border-radius: 0 12px 12px 0;">
                     <p class="security-text-dark" style="font-family: 'Inter', Arial, sans-serif; font-size: 15px; line-height: 1.7; margin: 0; color: #343a40;">
                        <strong style="color: #008080; font-weight: 700;">Security Note:</strong> This verification link expires in <strong>24 hours</strong>. Your account uses zero-knowledge encryption, meaning we never have access to your data.
                    </p>
                </td>
            </tr>
        </table>

        <p class="content-text" style="font-family: 'Inter', Arial, sans-serif; font-size: 17px; color: #495057; margin: 0 0 32px; line-height: 1.8;">
            If you didn't create an account with SVA, please disregard this email.
        </p>
        <p class="content-text" style="font-family: 'Inter', Arial, sans-serif; font-size: 17px; color: #495057; margin: 0; line-height: 1.8;">
            Best regards,<br />
            <strong style="color: #212529;">The SVA Security Team</strong>
        </p>
    """
    
    html_message = SVAEmailTemplate.create_email_html(
        title="Verify Your Email - SVA",
        header_title="One Last Step...",
        header_subtitle="Zero-Knowledge Security Platform",
        content_body=content_body
    )
    
    plain_message = f"""
    Verify Your Email - SVA Zero-Knowledge Authentication
    
    Hello! Thank you for registering with SVA. To complete your account setup, please verify your email address by visiting the following link:
    {verification_url}
    
    This link will expire in 24 hours. If you didn't create an account, please ignore this email.
    
    Best regards,
    The SVA Team
    """
    
    try:
        send_mail(
            subject=subject,
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
            html_message=html_message,
            fail_silently=False,
        )
        return True
    except Exception as e:
        print(f"Failed to send verification email to {email}: {str(e)}")
        return False


def send_welcome_email(email, user_id):
    subject = "Welcome to SVA - Your Account is Ready!"
    
    content_body = f"""
        <h2 class="greeting" style="font-family: 'Inter', Arial, sans-serif; font-size: 34px; font-weight: 800; margin: 0 0 24px; color: #008080; line-height: 1.2;">Account Successfully Verified!</h2>
        <p class="content-text" style="font-family: 'Inter', Arial, sans-serif; font-size: 17px; color: #495057; margin: 0 0 24px; line-height: 1.8;">
            Congratulations! Your SVA account has been successfully created and verified. You now have access to your secure Universal Profile.
        </p>
        
        <!-- Success Note -->
        <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="margin: 48px 0;">
            <tr>
                <td style="background-color: #e8f5e8; border-left: 5px solid #20c997; padding: 24px 28px; border-radius: 0 12px 12px 0;">
                     <p style="font-family: 'Inter', Arial, sans-serif; font-size: 15px; line-height: 1.7; margin: 0; color: #343a40;">
                        <strong>✅ Account Status:</strong> Active and verified<br>
                        <strong>🔐 Security Level:</strong> Zero-Knowledge Encryption<br>
                        <strong>🆔 Account ID:</strong> {user_id}
                    </p>
                </td>
            </tr>
        </table>
        
        <p class="content-text" style="font-family: 'Inter', Arial, sans-serif; font-size: 17px; color: #495057; margin: 0 0 32px; line-height: 1.8;">
            <strong>Important:</strong> Remember to keep your master key safe - it's the only way to decrypt your data. Your secrets remain forged only in your mind.
        </p>
        <p class="content-text" style="font-family: 'Inter', Arial, sans-serif; font-size: 17px; color: #495057; margin: 0; line-height: 1.8;">
            Welcome to the future of secure authentication!<br />
            <strong style="color: #212529;">The SVA Team</strong>
        </p>
    """
    
    html_message = SVAEmailTemplate.create_email_html(
        title="Welcome to SVA!",
        header_title="Welcome Aboard!",
        header_subtitle="Your Universal Profile is now active",
        content_body=content_body
    )
    
    plain_message = f"""
    Welcome to SVA - Your Account is Ready!
    Congratulations! Your SVA account has been successfully created and verified.
    Account ID: {user_id}
    Remember to keep your master key safe!
    Best regards,
    The SVA Team
    """
    
    try:
        send_mail(
            subject=subject,
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
            html_message=html_message,
            fail_silently=False,
        )
        return True
    except Exception as e:
        print(f"Failed to send welcome email to {email}: {str(e)}")
        return False


def send_password_reset_email(email, token, frontend_url=None):
    if not frontend_url:
        frontend_url = "http://localhost:8080"
    
    reset_url = f"{frontend_url}/reset-password?token={token}"
    subject = "Reset Your Password - SVA Security"
    
    content_body = f"""
        <h2 class="greeting" style="font-family: 'Inter', Arial, sans-serif; font-size: 34px; font-weight: 800; margin: 0 0 24px; color: #008080; line-height: 1.2;">Password Reset Request</h2>
        <p class="content-text" style="font-family: 'Inter', Arial, sans-serif; font-size: 17px; color: #495057; margin: 0 0 24px; line-height: 1.8;">
            We received a request to reset your password. If you made this request, click the button below.
        </p>

        <!-- Bulletproof Button -->
        <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="margin: 48px 0;">
            <tr>
                <td align="center">
                    <table role="presentation" border="0" cellpadding="0" cellspacing="0">
                        <tr>
                            <td class="button-cell" align="center" bgcolor="#20c997" style="border-radius: 10px; background: linear-gradient(135deg, #20c997 0%, #008080 100%);">
                                <a href="{reset_url}" target="_blank" style="font-family: 'Inter', Arial, sans-serif; font-size: 17px; font-weight: 700; color: #ffffff; text-decoration: none; display: inline-block; padding: 20px 48px; border-radius: 10px; border: 1px solid #20c997;">
                                    Reset Password &rarr;
                                </a>
                            </td>
                        </tr>
                    </table>
                </td>
            </tr>
        </table>
        
        <!-- Security Note -->
        <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="margin: 48px 0;">
            <tr>
                <td class="security-note-dark" style="background-color: #e6fcf5; border-left: 5px solid #20c997; padding: 24px 28px; border-radius: 0 12px 12px 0;">
                     <p class="security-text-dark" style="font-family: 'Inter', Arial, sans-serif; font-size: 15px; line-height: 1.7; margin: 0; color: #343a40;">
                        <strong style="color: #008080; font-weight: 700;">Security Note:</strong> This reset link expires in <strong>1 hour</strong>. If you didn't request this change, please ignore this email.
                    </p>
                </td>
            </tr>
        </table>
        <p class="content-text" style="font-family: 'Inter', Arial, sans-serif; font-size: 17px; color: #495057; margin: 0; line-height: 1.8;">
            Best regards,<br />
            <strong style="color: #212529;">The SVA Security Team</strong>
        </p>
    """
    
    html_message = SVAEmailTemplate.create_email_html(
        title="Reset Your Password - SVA",
        header_title="Password Reset Request",
        header_subtitle="Secure Account Recovery",
        content_body=content_body
    )
    
    plain_message = f"""
    Reset Your Password - SVA Security
    We received a request to reset your password for your SVA account. To reset your password, visit the following link:
    {reset_url}
    This link expires in 1 hour. If you didn't request this, please ignore this email.
    Best regards,
    The SVA Security Team
    """
    
    try:
        send_mail(
            subject=subject,
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
            html_message=html_message,
            fail_silently=False,
        )
        return True
    except Exception as e:
        print(f"Failed to send password reset email to {email}: {str(e)}")
        return False


def send_otp_email(email, otp_code, frontend_url=None):
    """
    Send OTP code via email for verifiable block verification
    Zero-Knowledge: Email is only used temporarily to send OTP, never stored long-term
    """
    if not frontend_url:
        frontend_url = "http://localhost:8080"
    
    subject = "Your SVA Verification Code"
    
    content_body = f"""
        <h2 class="greeting" style="font-family: 'Inter', Arial, sans-serif; font-size: 34px; font-weight: 800; margin: 0 0 24px; color: #008080; line-height: 1.2;">Verification Code</h2>
        <p class="content-text" style="font-family: 'Inter', Arial, sans-serif; font-size: 17px; color: #495057; margin: 0 0 24px; line-height: 1.8;">
            You requested to verify your email address. Use the code below to complete verification:
        </p>

        <!-- OTP Code Display -->
        <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="margin: 48px 0;">
            <tr>
                <td align="center">
                    <table role="presentation" border="0" cellpadding="0" cellspacing="0" style="border: 2px solid #20c997; border-radius: 12px; padding: 24px 40px; background: linear-gradient(135deg, #e6fcf5 0%, #c3fae8 100%);">
                        <tr>
                            <td align="center">
                                <div style="font-family: 'Inter', Arial, sans-serif; font-size: 36px; font-weight: 700; color: #008080; letter-spacing: 8px; margin: 0;">
                                    {otp_code}
                                </div>
                            </td>
                        </tr>
                    </table>
                </td>
            </tr>
        </table>
        
        <!-- Security Note -->
        <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="margin: 48px 0;">
            <tr>
                <td class="security-note-dark" style="background-color: #e6fcf5; border-left: 5px solid #20c997; padding: 24px 28px; border-radius: 0 12px 12px 0;">
                     <p class="security-text-dark" style="font-family: 'Inter', Arial, sans-serif; font-size: 15px; line-height: 1.7; margin: 0; color: #343a40;">
                        <strong style="color: #008080; font-weight: 700;">Security Note:</strong> This code expires in <strong>15 minutes</strong>. Never share this code with anyone. SVA will never ask for your verification code.
                    </p>
                </td>
            </tr>
        </table>

        <p class="content-text" style="font-family: 'Inter', Arial, sans-serif; font-size: 17px; color: #495057; margin: 0 0 32px; line-height: 1.8;">
            If you didn't request this verification code, please ignore this email.
        </p>
        <p class="content-text" style="font-family: 'Inter', Arial, sans-serif; font-size: 17px; color: #495057; margin: 0; line-height: 1.8;">
            Best regards,<br />
            <strong style="color: #212529;">The SVA Security Team</strong>
        </p>
    """
    
    html_message = SVAEmailTemplate.create_email_html(
        title="Your SVA Verification Code",
        header_title="Verify Your Identity",
        header_subtitle="Secure Verification Code",
        content_body=content_body
    )
    
    plain_message = f"""
    Your SVA Verification Code
    
    Your verification code is: {otp_code}
    
    This code expires in 15 minutes. Never share this code with anyone.
    
    If you didn't request this verification code, please ignore this email.
    
    Best regards,
    The SVA Security Team
    """
    
    try:
        send_mail(
            subject=subject,
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
            html_message=html_message,
            fail_silently=False,
        )
        return True
    except Exception as e:
        print(f"Failed to send OTP email to {email}: {str(e)}")
        return False


def send_otp_sms(phone_number, otp_code):
    """
    Send OTP code via SMS for verifiable block verification
    
    Zero-Knowledge: Phone number is only used temporarily to send OTP, never stored long-term
    
    Note: This is a placeholder implementation. In production, integrate with SMS provider:
    - Twilio
    - AWS SNS
    - MessageBird
    - etc.
    """
    # TODO: Integrate with actual SMS provider
    # For now, just log the OTP (for development/testing)
    print(f"[SMS OTP] Sending to {phone_number}: {otp_code}")
    
    # In production, replace with actual SMS sending:
    # try:
    #     sms_client = boto3.client('sns')  # Example with AWS SNS
    #     sms_client.publish(
    #         PhoneNumber=phone_number,
    #         Message=f"Your SVA verification code is: {otp_code}. This code expires in 15 minutes."
    #     )
    #     return True
    # except Exception as e:
    #     print(f"Failed to send OTP SMS to {phone_number}: {str(e)}")
    #     return False
    
    # For development, return True to simulate successful send
    return True


def send_account_locked_email(email, unlock_token, frontend_url=None):
    if not frontend_url:
        frontend_url = "http://localhost:8080"
    
    unlock_url = f"{frontend_url}/unlock-account?token={unlock_token}"
    subject = "Account Security Alert - SVA"
    
    content_body = f"""
        <h2 class="greeting" style="font-family: 'Inter', Arial, sans-serif; font-size: 34px; font-weight: 800; margin: 0 0 24px; color: #008080; line-height: 1.2;">Account Security Alert</h2>
        <p class="content-text" style="font-family: 'Inter', Arial, sans-serif; font-size: 17px; color: #495057; margin: 0 0 24px; line-height: 1.8;">
            Your SVA account has been temporarily locked due to multiple failed login attempts. This is a security measure to protect your account.
        </p>

        <!-- Bulletproof Button -->
        <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="margin: 48px 0;">
            <tr>
                <td align="center">
                    <table role="presentation" border="0" cellpadding="0" cellspacing="0">
                        <tr>
                            <td class="button-cell" align="center" bgcolor="#20c997" style="border-radius: 10px; background: linear-gradient(135deg, #20c997 0%, #008080 100%);">
                                <a href="{unlock_url}" target="_blank" style="font-family: 'Inter', Arial, sans-serif; font-size: 17px; font-weight: 700; color: #ffffff; text-decoration: none; display: inline-block; padding: 20px 48px; border-radius: 10px; border: 1px solid #20c997;">
                                    Unlock Account &rarr;
                                </a>
                            </td>
                        </tr>
                    </table>
                </td>
            </tr>
        </table>
        
        <p class="content-text" style="font-family: 'Inter', Arial, sans-serif; font-size: 17px; color: #495057; margin: 0 0 32px; line-height: 1.8;">
            If you did not attempt to log in, please contact our security team immediately.
        </p>
        <p class="content-text" style="font-family: 'Inter', Arial, sans-serif; font-size: 17px; color: #495057; margin: 0; line-height: 1.8;">
            Best regards,<br />
            <strong style="color: #212529;">The SVA Security Team</strong>
        </p>
    """
    
    html_message = SVAEmailTemplate.create_email_html(
        title="Account Security Alert - SVA",
        header_title="Account Locked",
        header_subtitle="Security Protection Activated",
        content_body=content_body
    )
    
    plain_message = f"""
    Account Security Alert - SVA
    Your SVA account has been temporarily locked due to multiple failed login attempts. To unlock your account, visit the following link:
    {unlock_url}
    If you didn't attempt to access your account, please contact our security team immediately.
    Best regards,
    The SVA Security Team
    """
    
    try:
        send_mail(
            subject=subject,
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
            html_message=html_message,
            fail_silently=False,
        )
        return True
    except Exception as e:
        print(f"Failed to send account locked email to {email}: {str(e)}")
        return False