<?php namespace Jenssegers\Mongodb\Auth;

use DateTime;
use DateTimeZone;
use Illuminate\Auth\Passwords\DatabaseTokenRepository as BaseDatabaseTokenRepository;
use MongoDB\BSON\UTCDateTime;

class DatabaseTokenRepository extends BaseDatabaseTokenRepository
{
    /**
     * @inheritdoc
     */
    protected function getPayload($email, $token)
    {
       // Hash token
        return ['email' => $email, 'token' => $this->hasher->make($token), 'created_at' => new UTCDateTime(time() * 1000)];
    }

    /**
     * @inheritdoc
     */
    protected function tokenExpired($token)
    {
        // Added this first if
        if($token instanceof UTCDateTime) {

            $date = $token->toDateTime();
            $date->setTimezone(new DateTimeZone(date_default_timezone_get()));

            $createdAt = $date->format('Y-m-d H:i:s');

            return parent::tokenExpired($createdAt);
        }

        // Convert UTCDateTime to a date string.
        elseif ($token['created_at'] instanceof UTCDateTime) {

            $date = $token['created_at']->toDateTime();
            $date->setTimezone(new DateTimeZone(date_default_timezone_get()));
            $token['created_at'] = $date->format('Y-m-d H:i:s');

        } elseif (is_array($token['created_at']) and isset($token['created_at']['date'])) {

            $date = new DateTime($token['created_at']['date'], new DateTimeZone(isset($token['created_at']['timezone']) ? $token['created_at']['timezone'] : 'UTC'));
            $date->setTimezone(new DateTimeZone(date_default_timezone_get()));
            $token['created_at'] = $date->format('Y-m-d H:i:s');
        }


        return parent::tokenExpired($token);
    }
}
