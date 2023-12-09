CREATE OR REPLACE FUNCTION update_average_rating()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        UPDATE books
        SET average_rating = (
            SELECT COALESCE(AVG(rating), 0.0)
            FROM book_ratings
            WHERE book_ratings.book_id = OLD.book_id
        )
        WHERE books.book_id = OLD.book_id;
    ELSE
        UPDATE books
        SET average_rating = (
            SELECT COALESCE(AVG(rating), 0.0)
            FROM book_ratings
            WHERE book_ratings.book_id = NEW.book_id
        )
        WHERE books.book_id = NEW.book_id;
    END IF;

    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_average_rating_trigger
AFTER INSERT OR UPDATE OR DELETE ON book_ratings
FOR EACH ROW EXECUTE FUNCTION update_average_rating();

