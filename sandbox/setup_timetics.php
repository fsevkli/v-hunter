<?php
$appt_id  = 8;
$staff_id = 1;

// Duration must be "X min" or "X hr" format
update_post_meta($appt_id, '_tt_apointment_duration', '60 min');

// Timezone — required by convert_timezone
update_post_meta($appt_id, '_tt_apointment_timezone', 'UTC');

// Staff IDs
update_post_meta($appt_id, '_tt_apointment_staff', [$staff_id]);

// Schedule keyed by staff_id => day abbreviation (ucfirst 3-letter)
update_post_meta($appt_id, '_tt_apointment_schedule', [
    $staff_id => [
        'Mon' => [['start' => '09:00', 'end' => '17:00']],
        'Tue' => [['start' => '09:00', 'end' => '17:00']],
        'Wed' => [['start' => '09:00', 'end' => '17:00']],
        'Thu' => [['start' => '09:00', 'end' => '17:00']],
        'Fri' => [['start' => '09:00', 'end' => '17:00']],
    ],
]);

// Location
update_post_meta($appt_id, '_tt_apointment_locations', [
    ['location_type' => 'in-person-meeting', 'location' => 'Test Office'],
]);

update_post_meta($appt_id, '_tt_apointment_price', 50);

echo "Done updating appointment $appt_id\n";

// Verify with the model
$appt = new \Timetics\Core\Appointments\Appointment($appt_id);
echo "Duration: " . $appt->get_duration() . "\n";
echo "Timezone: " . $appt->get_timezone() . "\n";
echo "Staff IDs: " . implode(', ', (array) $appt->get_staff_ids()) . "\n";
echo "Locations: " . json_encode($appt->get_locations()) . "\n";

$slots = $appt->get_avilable_timeslots('2026-06-01', $staff_id, 'UTC');
echo "Timeslots for 2026-06-01 (Monday): " . implode(', ', $slots) . "\n";
