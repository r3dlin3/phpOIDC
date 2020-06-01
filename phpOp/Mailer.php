<?php

use PHPMailer\PHPMailer\PHPMailer;

class Mailer
{

    protected $transport;
    protected $options;

    public function __construct($options = array())
    {

        $this->options = $options;
        $this->transport = (array_key_exists('transport', $options)) ? $options['transport'] : 'mail';
    }

    /**
     * @return void
     */
    private function initSmtpTransport($mail)
    {
        if ($this->transport == 'smtp') {

            $mail->isSMTP();

            if (isset($this->options['host']) && $this->options['host']) {
                $mail->Host = $this->options['host']; // Specify main and backup server
            }

            if (array_key_exists('auth', $this->options)) {
                $mail->SMTPAuth = $this->options['auth']; // Enable SMTP authentication
            }

            if (isset($this->options['user']) && $this->options['user']) {
                $mail->Username = $this->options['user']; // SMTP username
            }

            if (isset($this->options['password']) && $this->options['password']) {
                $mail->Password = $this->options['password']; // SMTP password
            }

            if (isset($this->options['port']) && $this->options['port']) {
                $mail->Port = $this->options['port']; // smtp port
            }

            if (array_key_exists('encryption', $this->options)) {
                $mail->SMTPSecure = $this->options['encryption']; // Enable encryption: 'ssl' , 'tls' accepted
            }

            if (array_key_exists('auto_tls', $this->options)) {
                $mail->SMTPAutoTLS = $this->options['auto_tls']; // Whether to enable TLS encryption automatically if a server supports it, even if `SMTPSecure` is not set to 'tls'.
            }

        }
    }

    public function mail($to, $subject, $message, $options = [])
    {
        $options = array_merge($this->options, is_array($options) ? $options : []);

        $mail = new PHPMailer(true);
        $this->initSmtpTransport($mail);

        $mail->Subject = $subject;
        $mail->Body    = $message;
        $mail->CharSet = PHPMailer::CHARSET_UTF8;

        $mail->IsHTML($message !=  strip_tags($message)); // auto-set email format to HTML

        if (is_string($to)) {
            $to_array = explode(',', $to);
        } else {
            $to_array = $to ?? [];
        }

        foreach ($to_array as $to_single) {
            $mail->addAddress($to_single);
        }

        if (isset($options['altMessage']) && $options['altMessage']) {
            $mail->AltBody = $options['altMessage'];
        }

        if (isset($options['embedded'])) {
            foreach ($options['embedded'] as $id => $file) {
                $mail->AddEmbeddedImage($file, $id);
            }
        }

        if (isset($options['attachments'])) {

            foreach ($options['attachments'] as $id => $file) {

                if (is_string($id)) {
                    $mail->addStringAttachment($file, $id);
                } else {
                    $mail->addAttachment($file);
                }
            }
        }

        if (isset($options['cc'])) {
            foreach ($options['cc'] as $email) {
                $mail->AddCC($email);
            }
        }

        if (isset($options['bcc'])) {
            foreach ($options['bcc'] as $email) {
                $mail->addBCC($email);
            }
        }

        if (isset($options['from'])) {
            // $fromName = isset($options['from_name']) ? $options['from_name'] : $options['from'];
            $mail->setFrom($options['from'], $options['from_name'] ?? $options['from']);
        }

        if (isset($options['reply_to'])) {
            $mail->addReplyTo($options['reply_to']);
        }

        $mail->send();
    }
}
