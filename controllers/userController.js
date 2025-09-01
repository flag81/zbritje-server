import { queryPromise } from '../dbUtils.js';

/**
 * GET /user/profile
 * Retrieves the profile for the currently authenticated user.
 */
export const getUserProfile = async (req, res) => {
    if (!req.identifiedUser?.id) {
        return res.status(401).json({ error: 'User identification required.' });
    }
    try {
        const q = 'SELECT first_name, last_name, email, notification_frequency FROM users WHERE id = ?';
        const [user] = await queryPromise(q, [req.identifiedUser.id]);
        if (!user) {
            return res.status(404).json({ error: 'User not found.' });
        }
        res.json({
            firstName: user.first_name,
            lastName: user.last_name,
            email: user.email,
            notificationFrequency: user.notification_frequency
        });
    } catch (err) {
        console.error('[API] Error getting user profile:', err);
        res.status(500).json({ error: 'Failed to get profile.' });
    }
};

/**
 * PUT /user/profile
 * Updates the profile for the currently authenticated user.
 */
export const updateUserProfile = async (req, res) => {
    if (!req.identifiedUser?.id) {
        return res.status(401).json({ error: 'User identification required.' });
    }

    const { firstName, lastName, email, notificationFrequency } = req.body;
    const validFrequencies = ['daily', 'weekly', 'monthly', 'off'];

    if (notificationFrequency && !validFrequencies.includes(notificationFrequency)) {
        return res.status(400).json({ error: 'Invalid notification frequency value.' });
    }

    try {
        const q = `
            UPDATE users 
            SET first_name = ?, last_name = ?, email = ?, notification_frequency = ? 
            WHERE id = ?
        `;
        await queryPromise(q, [
            firstName,
            lastName,
            email,
            notificationFrequency,
            req.identifiedUser.id
        ]);
        res.json({ message: 'Profile updated successfully.' });
    } catch (err) {
        console.error('[API] Error updating user profile:', err);
        res.status(500).json({ error: 'Failed to update profile.' });
    }
};